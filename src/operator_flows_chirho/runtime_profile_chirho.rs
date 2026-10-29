// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Builds and verifies runtime-profile package manifests without changing executable bytes.

use crate::model_chirho::{CapabilityChirho, DagChirho, HashChirho, NodeDefChirho, PortChirho};
use crate::{compile_chirho, dag_module_chirho, store_chirho};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::BTreeSet;
use std::path::Path;

pub use cairn_model_runtime_chirho::{
    ensure_public_runtime_package_artifact_chirho, is_public_runtime_profile_chirho,
    RuntimePackageChirho, RuntimePackageItemKindChirho, RuntimeProfileKindChirho, BYTES_ABI_CHIRHO,
};

pub fn build_runtime_package_chirho(
    root_chirho: &Path,
    module_hash_chirho: &HashChirho,
    profile_chirho: RuntimeProfileKindChirho,
) -> Result<(RuntimePackageChirho, HashChirho)> {
    let module_chirho =
        dag_module_chirho::validate_stored_dag_module_chirho(root_chirho, module_hash_chirho)?;
    let dag_chirho: DagChirho =
        store_chirho::get_object_chirho(root_chirho, &module_chirho.dag_chirho)?;
    let node_defs_chirho = load_module_node_defs_chirho(root_chirho, &dag_chirho)?;
    let capabilities_chirho = module_capabilities_chirho(&dag_chirho, &node_defs_chirho)?;
    if !capabilities_chirho.is_empty() {
        bail!("runtime package v1 handles pure modules only; effect imports are host-profile work");
    }
    let entry_chirho = runtime_package_entry_chirho(&node_defs_chirho)?;
    let executable_chirho = compile_chirho::compile_dag_chirho(root_chirho, &dag_chirho)
        .with_context(|| "compile runtime package executable")?;
    let (included_items_chirho, excluded_items_chirho) = profile_items_chirho(profile_chirho);
    let object_hashes_chirho = profile_object_hashes_chirho(
        root_chirho,
        profile_chirho,
        module_hash_chirho,
        &executable_chirho,
    )?;
    let package_chirho = RuntimePackageChirho {
        profile_chirho,
        module_chirho: module_hash_chirho.clone(),
        dag_chirho: module_chirho.dag_chirho.clone(),
        executable_chirho,
        entry_chirho,
        abi_chirho: BYTES_ABI_CHIRHO.to_string(),
        inputs_chirho: module_chirho
            .inputs_chirho
            .iter()
            .map(|port_chirho| port_chirho.public_port_chirho.clone())
            .collect(),
        outputs_chirho: module_chirho
            .outputs_chirho
            .iter()
            .map(|port_chirho| port_chirho.public_port_chirho.clone())
            .collect(),
        capabilities_chirho,
        included_items_chirho,
        excluded_items_chirho,
        object_hashes_chirho,
    };
    validate_runtime_package_chirho(root_chirho, &package_chirho)?;
    let package_hash_chirho = store_chirho::put_object_chirho(root_chirho, &package_chirho)?;
    Ok((package_chirho, package_hash_chirho))
}

pub fn load_runtime_package_chirho(
    root_chirho: &Path,
    package_chirho: &HashChirho,
) -> Result<RuntimePackageChirho> {
    store_chirho::get_object_chirho(root_chirho, package_chirho).with_context(|| {
        format!(
            "RuntimePackageChirho {} is not in the store",
            package_chirho.0
        )
    })
}

pub fn validate_stored_runtime_package_chirho(
    root_chirho: &Path,
    package_chirho: &HashChirho,
) -> Result<RuntimePackageChirho> {
    let package_obj_chirho = load_runtime_package_chirho(root_chirho, package_chirho)?;
    validate_runtime_package_chirho(root_chirho, &package_obj_chirho)?;
    Ok(package_obj_chirho)
}

pub fn validate_public_runtime_package_chirho(
    root_chirho: &Path,
    package_chirho: &HashChirho,
) -> Result<RuntimePackageChirho> {
    let package_obj_chirho = validate_stored_runtime_package_chirho(root_chirho, package_chirho)?;
    ensure_public_runtime_package_artifact_chirho(&package_obj_chirho)?;
    Ok(package_obj_chirho)
}

pub fn validate_runtime_package_chirho(
    root_chirho: &Path,
    package_chirho: &RuntimePackageChirho,
) -> Result<()> {
    if package_chirho.abi_chirho != BYTES_ABI_CHIRHO {
        bail!(
            "runtime package ABI '{}' is not supported",
            package_chirho.abi_chirho
        );
    }
    let module_chirho = dag_module_chirho::validate_stored_dag_module_chirho(
        root_chirho,
        &package_chirho.module_chirho,
    )?;
    if module_chirho.dag_chirho != package_chirho.dag_chirho {
        bail!(
            "runtime package dag {} does not match module dag {}",
            package_chirho.dag_chirho.0,
            module_chirho.dag_chirho.0
        );
    }
    let dag_chirho: DagChirho =
        store_chirho::get_object_chirho(root_chirho, &module_chirho.dag_chirho)?;
    let node_defs_chirho = load_module_node_defs_chirho(root_chirho, &dag_chirho)?;
    let capabilities_chirho = module_capabilities_chirho(&dag_chirho, &node_defs_chirho)?;
    if !capabilities_chirho.is_empty() {
        bail!("runtime package v1 handles pure modules only; effect imports are host-profile work");
    }
    if capabilities_chirho != package_chirho.capabilities_chirho {
        bail!("runtime package import manifest does not match module capabilities");
    }
    let entry_chirho = runtime_package_entry_chirho(&node_defs_chirho)?;
    if entry_chirho != package_chirho.entry_chirho {
        bail!(
            "runtime package entry '{}' does not match module entry '{}'",
            package_chirho.entry_chirho,
            entry_chirho
        );
    }
    let inputs_chirho: Vec<PortChirho> = module_chirho
        .inputs_chirho
        .iter()
        .map(|port_chirho| port_chirho.public_port_chirho.clone())
        .collect();
    if inputs_chirho != package_chirho.inputs_chirho {
        bail!("runtime package inputs do not match module public inputs");
    }
    let outputs_chirho: Vec<PortChirho> = module_chirho
        .outputs_chirho
        .iter()
        .map(|port_chirho| port_chirho.public_port_chirho.clone())
        .collect();
    if outputs_chirho != package_chirho.outputs_chirho {
        bail!("runtime package outputs do not match module public outputs");
    }
    let executable_chirho = compile_chirho::compile_dag_chirho(root_chirho, &dag_chirho)
        .with_context(|| "recompile runtime package executable")?;
    if executable_chirho != package_chirho.executable_chirho {
        bail!(
            "runtime package executable {} does not match recomputed {}",
            package_chirho.executable_chirho.0,
            executable_chirho.0
        );
    }
    let (included_items_chirho, excluded_items_chirho) =
        profile_items_chirho(package_chirho.profile_chirho);
    if included_items_chirho != package_chirho.included_items_chirho {
        bail!("runtime package included item policy does not match profile");
    }
    if excluded_items_chirho != package_chirho.excluded_items_chirho {
        bail!("runtime package excluded item policy does not match profile");
    }
    let object_hashes_chirho = profile_object_hashes_chirho(
        root_chirho,
        package_chirho.profile_chirho,
        &package_chirho.module_chirho,
        &package_chirho.executable_chirho,
    )?;
    if object_hashes_chirho != package_chirho.object_hashes_chirho {
        bail!("runtime package object set does not match profile policy");
    }
    Ok(())
}

fn load_module_node_defs_chirho(
    root_chirho: &Path,
    dag_chirho: &DagChirho,
) -> Result<Vec<NodeDefChirho>> {
    dag_chirho
        .nodes_chirho
        .iter()
        .map(|node_chirho| {
            store_chirho::get_object_chirho(root_chirho, node_chirho)
                .with_context(|| format!("DAG node {} is not in the store", node_chirho.0))
        })
        .collect()
}

fn module_capabilities_chirho(
    dag_chirho: &DagChirho,
    node_defs_chirho: &[NodeDefChirho],
) -> Result<Vec<CapabilityChirho>> {
    if dag_chirho.nodes_chirho.len() != node_defs_chirho.len() {
        bail!("DAG node and node-def counts diverged");
    }
    let mut capabilities_chirho = Vec::new();
    for node_def_chirho in node_defs_chirho {
        capabilities_chirho.extend(node_def_chirho.capabilities_chirho.iter().cloned());
    }
    Ok(capabilities_chirho)
}

fn runtime_package_entry_chirho(node_defs_chirho: &[NodeDefChirho]) -> Result<String> {
    let [node_chirho] = node_defs_chirho else {
        bail!(
            "runtime package v1 needs exactly one node entry; found {} nodes",
            node_defs_chirho.len()
        );
    };
    if node_chirho.entry_chirho.trim().is_empty() {
        bail!("runtime package node entry must not be empty");
    }
    Ok(node_chirho.entry_chirho.clone())
}

fn profile_items_chirho(
    profile_chirho: RuntimeProfileKindChirho,
) -> (
    Vec<RuntimePackageItemKindChirho>,
    Vec<RuntimePackageItemKindChirho>,
) {
    use RuntimePackageItemKindChirho::*;
    match profile_chirho {
        RuntimeProfileKindChirho::BrowserChirho | RuntimeProfileKindChirho::EmbeddedChirho => (
            vec![
                ExecutableWasmChirho,
                BytesAbiChirho,
                PortSchemaHashesChirho,
                ImportManifestChirho,
            ],
            vec![
                ModuleDescriptorChirho,
                DagDescriptorChirho,
                NodeDescriptorsChirho,
                WasmSourceObjectsChirho,
                LedgerDescriptorsChirho,
                ResourceDescriptorsChirho,
                OwnerDescriptorsChirho,
                SchedulerDescriptorsChirho,
                ProvenanceDescriptorsChirho,
            ],
        ),
        RuntimeProfileKindChirho::ServerChirho => (
            vec![
                ExecutableWasmChirho,
                BytesAbiChirho,
                PortSchemaHashesChirho,
                ImportManifestChirho,
                ModuleDescriptorChirho,
                DagDescriptorChirho,
                NodeDescriptorsChirho,
                WasmSourceObjectsChirho,
                LedgerDescriptorsChirho,
                ResourceDescriptorsChirho,
                OwnerDescriptorsChirho,
                SchedulerDescriptorsChirho,
                ProvenanceDescriptorsChirho,
            ],
            Vec::new(),
        ),
    }
}

fn profile_object_hashes_chirho(
    root_chirho: &Path,
    profile_chirho: RuntimeProfileKindChirho,
    module_chirho: &HashChirho,
    executable_chirho: &HashChirho,
) -> Result<Vec<HashChirho>> {
    let mut hashes_chirho = BTreeSet::new();
    hashes_chirho.insert(executable_chirho.clone());
    if profile_chirho == RuntimeProfileKindChirho::ServerChirho {
        for (hash_chirho, _bytes_chirho) in
            crate::object_graph_chirho::gather_closure_chirho(root_chirho, module_chirho)?
        {
            hashes_chirho.insert(HashChirho(hash_chirho));
        }
    }
    Ok(hashes_chirho.into_iter().collect())
}

pub fn parse_runtime_profile_kind_chirho(profile_chirho: &str) -> Result<RuntimeProfileKindChirho> {
    match profile_chirho {
        "browser-chirho" | "browser" => Ok(RuntimeProfileKindChirho::BrowserChirho),
        "embedded-chirho" | "embedded" => Ok(RuntimeProfileKindChirho::EmbeddedChirho),
        "server-chirho" | "server" => Ok(RuntimeProfileKindChirho::ServerChirho),
        other_chirho => Err(anyhow!(
            "unknown runtime profile '{other_chirho}'; expected browser-chirho, embedded-chirho, or server-chirho"
        )),
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::dag_module_chirho::{DagModuleBindingInputChirho, DagModuleBuildInputChirho};
    use crate::model_chirho::{DagChirho, NodeDefChirho};
    use crate::{cas_chirho, dag_module_chirho, runner_chirho};
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
        std::env::temp_dir().join(format!(
            "cairn-runtime-profile-test-{nanos_chirho}-{n_chirho}"
        ))
    }

    fn module_chirho(
        root_chirho: &Path,
        capabilities_chirho: Vec<CapabilityChirho>,
    ) -> (HashChirho, HashChirho) {
        let schema_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
        let wasm_chirho = cas_chirho::add_chirho(
            root_chirho,
            include_str!("../../examples-chirho/upcase-chirho.wat").as_bytes(),
        )
        .unwrap();
        let node_chirho = NodeDefChirho {
            name_chirho: "upcase_chirho".to_string(),
            impl_wasm_chirho: wasm_chirho,
            entry_chirho: "upcase_chirho".to_string(),
            inputs_chirho: vec![PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: schema_chirho.clone(),
            }],
            outputs_chirho: vec![PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho,
            }],
            capabilities_chirho,
            fuel_limit_chirho: 1_000_000,
            ..Default::default()
        };
        let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
        let dag_chirho = DagChirho {
            nodes_chirho: vec![node_hash_chirho.clone()],
            edges_chirho: Vec::new(),
        };
        let dag_hash_chirho = store_chirho::put_object_chirho(root_chirho, &dag_chirho).unwrap();
        let (_module_chirho, module_hash_chirho) = dag_module_chirho::build_dag_module_chirho(
            root_chirho,
            DagModuleBuildInputChirho {
                name_chirho: "runtime-module-chirho".to_string(),
                dag_chirho: dag_hash_chirho,
                version_chirho: "v1".to_string(),
                previous_module_chirho: None,
                input_bindings_chirho: vec![DagModuleBindingInputChirho {
                    public_name_chirho: "request".to_string(),
                    node_chirho: node_hash_chirho.clone(),
                    node_port_chirho: "in".to_string(),
                }],
                output_bindings_chirho: vec![DagModuleBindingInputChirho {
                    public_name_chirho: "response".to_string(),
                    node_chirho: node_hash_chirho,
                    node_port_chirho: "out".to_string(),
                }],
                route_labels_chirho: Vec::new(),
                metadata_chirho: BTreeMap::new(),
            },
        )
        .unwrap();
        (module_hash_chirho, dag_chirho.nodes_chirho[0].clone())
    }

    fn pure_module_chirho(root_chirho: &Path) -> (HashChirho, HashChirho) {
        module_chirho(root_chirho, Vec::new())
    }

    fn effect_module_chirho(root_chirho: &Path) -> (HashChirho, HashChirho) {
        module_chirho(
            root_chirho,
            vec![CapabilityChirho::WriteStoreChirho {
                prefix_chirho: "runtime-package-secret-chirho".to_string(),
            }],
        )
    }

    #[test]
    fn lean_profiles_exclude_server_descriptors_but_share_executable_chirho() {
        let root_chirho = tmp_root_chirho();
        let (module_hash_chirho, _node_hash_chirho) = pure_module_chirho(&root_chirho);

        let (browser_chirho, browser_hash_chirho) = build_runtime_package_chirho(
            &root_chirho,
            &module_hash_chirho,
            RuntimeProfileKindChirho::BrowserChirho,
        )
        .unwrap();
        let (embedded_chirho, _embedded_hash_chirho) = build_runtime_package_chirho(
            &root_chirho,
            &module_hash_chirho,
            RuntimeProfileKindChirho::EmbeddedChirho,
        )
        .unwrap();
        let (server_chirho, server_hash_chirho) = build_runtime_package_chirho(
            &root_chirho,
            &module_hash_chirho,
            RuntimeProfileKindChirho::ServerChirho,
        )
        .unwrap();

        assert_eq!(
            browser_chirho.executable_chirho,
            embedded_chirho.executable_chirho
        );
        assert_eq!(
            browser_chirho.executable_chirho,
            server_chirho.executable_chirho
        );
        assert_eq!(browser_chirho.entry_chirho, "upcase_chirho");
        assert_eq!(embedded_chirho.entry_chirho, browser_chirho.entry_chirho);
        assert_eq!(server_chirho.entry_chirho, browser_chirho.entry_chirho);
        let browser_executable_chirho =
            cas_chirho::get_chirho(&root_chirho, &browser_chirho.executable_chirho).unwrap();
        let outcome_chirho = runner_chirho::run_node_bytes_chirho(
            &browser_executable_chirho,
            &browser_chirho.entry_chirho,
            b"browser package",
            1_000_000,
        )
        .unwrap();
        assert_eq!(outcome_chirho.output_chirho, b"BROWSER PACKAGE");
        assert_eq!(
            browser_chirho.object_hashes_chirho,
            vec![browser_chirho.executable_chirho.clone()]
        );
        assert!(browser_chirho
            .excluded_items_chirho
            .contains(&RuntimePackageItemKindChirho::LedgerDescriptorsChirho));
        assert!(browser_chirho
            .excluded_items_chirho
            .contains(&RuntimePackageItemKindChirho::ResourceDescriptorsChirho));
        assert!(browser_chirho
            .excluded_items_chirho
            .contains(&RuntimePackageItemKindChirho::OwnerDescriptorsChirho));
        assert!(browser_chirho
            .excluded_items_chirho
            .contains(&RuntimePackageItemKindChirho::SchedulerDescriptorsChirho));
        assert!(server_chirho
            .included_items_chirho
            .contains(&RuntimePackageItemKindChirho::LedgerDescriptorsChirho));
        assert!(server_chirho
            .object_hashes_chirho
            .contains(&module_hash_chirho));
        assert!(server_chirho
            .object_hashes_chirho
            .contains(&server_chirho.executable_chirho));
        validate_stored_runtime_package_chirho(&root_chirho, &browser_hash_chirho).unwrap();
        validate_stored_runtime_package_chirho(&root_chirho, &server_hash_chirho).unwrap();
        validate_public_runtime_package_chirho(&root_chirho, &browser_hash_chirho).unwrap();
        assert!(ensure_public_runtime_package_artifact_chirho(&embedded_chirho).is_ok());
        assert!(ensure_public_runtime_package_artifact_chirho(&server_chirho).is_err());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn public_runtime_package_contract_is_capability_free_and_executable_only_chirho() {
        let root_chirho = tmp_root_chirho();
        let (module_hash_chirho, _node_hash_chirho) = pure_module_chirho(&root_chirho);
        let (browser_chirho, _browser_hash_chirho) = build_runtime_package_chirho(
            &root_chirho,
            &module_hash_chirho,
            RuntimeProfileKindChirho::BrowserChirho,
        )
        .unwrap();

        assert!(is_public_runtime_profile_chirho(
            RuntimeProfileKindChirho::BrowserChirho
        ));
        assert!(is_public_runtime_profile_chirho(
            RuntimeProfileKindChirho::EmbeddedChirho
        ));
        assert!(!is_public_runtime_profile_chirho(
            RuntimeProfileKindChirho::ServerChirho
        ));

        let mut capability_package_chirho = browser_chirho.clone();
        capability_package_chirho
            .capabilities_chirho
            .push(CapabilityChirho::ClockChirho);
        assert!(ensure_public_runtime_package_artifact_chirho(&capability_package_chirho).is_err());

        let mut extra_object_package_chirho = browser_chirho;
        extra_object_package_chirho
            .object_hashes_chirho
            .push(module_hash_chirho);
        assert!(
            ensure_public_runtime_package_artifact_chirho(&extra_object_package_chirho).is_err()
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn runtime_package_rejects_effect_capability_modules_chirho() {
        let root_chirho = tmp_root_chirho();
        let (pure_module_hash_chirho, _pure_node_hash_chirho) = pure_module_chirho(&root_chirho);
        let (effect_module_hash_chirho, _effect_node_hash_chirho) =
            effect_module_chirho(&root_chirho);

        assert!(build_runtime_package_chirho(
            &root_chirho,
            &effect_module_hash_chirho,
            RuntimeProfileKindChirho::BrowserChirho,
        )
        .is_err());

        let (mut package_chirho, _package_hash_chirho) = build_runtime_package_chirho(
            &root_chirho,
            &pure_module_hash_chirho,
            RuntimeProfileKindChirho::BrowserChirho,
        )
        .unwrap();
        let effect_module_chirho = dag_module_chirho::validate_stored_dag_module_chirho(
            &root_chirho,
            &effect_module_hash_chirho,
        )
        .unwrap();
        package_chirho.module_chirho = effect_module_hash_chirho;
        package_chirho.dag_chirho = effect_module_chirho.dag_chirho;

        assert!(validate_runtime_package_chirho(&root_chirho, &package_chirho).is_err());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn runtime_package_validation_rejects_wrong_executable_chirho() {
        let root_chirho = tmp_root_chirho();
        let (module_hash_chirho, node_hash_chirho) = pure_module_chirho(&root_chirho);
        let (mut package_chirho, _package_hash_chirho) = build_runtime_package_chirho(
            &root_chirho,
            &module_hash_chirho,
            RuntimeProfileKindChirho::BrowserChirho,
        )
        .unwrap();
        package_chirho.executable_chirho = node_hash_chirho;
        assert!(validate_runtime_package_chirho(&root_chirho, &package_chirho).is_err());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn runtime_package_validation_rejects_wrong_entry_chirho() {
        let root_chirho = tmp_root_chirho();
        let (module_hash_chirho, _node_hash_chirho) = pure_module_chirho(&root_chirho);
        let (mut package_chirho, _package_hash_chirho) = build_runtime_package_chirho(
            &root_chirho,
            &module_hash_chirho,
            RuntimeProfileKindChirho::BrowserChirho,
        )
        .unwrap();
        package_chirho.entry_chirho = "run_chirho".to_string();
        assert!(validate_runtime_package_chirho(&root_chirho, &package_chirho).is_err());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
