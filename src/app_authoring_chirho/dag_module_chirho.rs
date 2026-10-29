// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Validates stored DAG module descriptors and typed compositions that lower to flat DAGs.

use crate::model_chirho::{
    DagChirho, DagModuleChirho, DagModuleCompositionChirho, DagModuleCompositionPortChirho,
    DagModuleInstanceChirho, DagModulePortChirho, DagModuleWireChirho, EdgeChirho, HashChirho,
    NodeDefChirho, PortChirho,
};
use crate::{dag_chirho, store_chirho};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DagModuleBuildInputChirho {
    pub name_chirho: String,
    pub dag_chirho: HashChirho,
    pub version_chirho: String,
    pub previous_module_chirho: Option<HashChirho>,
    pub input_bindings_chirho: Vec<DagModuleBindingInputChirho>,
    pub output_bindings_chirho: Vec<DagModuleBindingInputChirho>,
    pub route_labels_chirho: Vec<String>,
    pub metadata_chirho: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DagModuleBindingInputChirho {
    pub public_name_chirho: String,
    pub node_chirho: HashChirho,
    pub node_port_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DagModuleCompositionBuildInputChirho {
    pub name_chirho: String,
    pub version_chirho: String,
    pub instances_chirho: Vec<DagModuleInstanceInputChirho>,
    pub wires_chirho: Vec<DagModuleWireInputChirho>,
    pub input_bindings_chirho: Vec<DagModuleCompositionBindingInputChirho>,
    pub output_bindings_chirho: Vec<DagModuleCompositionBindingInputChirho>,
    pub metadata_chirho: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DagModuleInstanceInputChirho {
    pub instance_chirho: String,
    pub module_chirho: HashChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DagModuleWireInputChirho {
    pub from_instance_chirho: String,
    pub from_port_chirho: String,
    pub to_instance_chirho: String,
    pub to_port_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DagModuleCompositionBindingInputChirho {
    pub public_name_chirho: String,
    pub instance_chirho: String,
    pub module_port_chirho: String,
}

#[derive(Clone, Debug)]
pub struct DagModuleCompositionRunReportChirho {
    pub composition_chirho: DagModuleCompositionChirho,
    pub dag_report_chirho: dag_chirho::DagRunReportChirho,
    pub instance_runs_chirho: Vec<DagModuleInstanceRunChirho>,
}

#[derive(Clone, Debug)]
pub struct DagModuleInstanceRunChirho {
    pub instance_chirho: String,
    pub module_chirho: HashChirho,
    pub node_runs_chirho: Vec<dag_chirho::NodeRunChirho>,
}

pub fn build_dag_module_chirho(
    root_chirho: &Path,
    input_chirho: DagModuleBuildInputChirho,
) -> Result<(DagModuleChirho, HashChirho)> {
    let dag_chirho: DagChirho =
        store_chirho::get_object_chirho(root_chirho, &input_chirho.dag_chirho).with_context(
            || {
                format!(
                    "wrapped DagChirho {} is not in the store",
                    input_chirho.dag_chirho.0
                )
            },
        )?;
    let node_defs_chirho = load_node_defs_chirho(root_chirho, &dag_chirho)?;
    validate_safe_token_chirho("module name", &input_chirho.name_chirho)?;
    validate_safe_token_chirho("module version", &input_chirho.version_chirho)?;
    for route_chirho in &input_chirho.route_labels_chirho {
        validate_safe_token_chirho("route label", route_chirho)?;
    }
    for key_chirho in input_chirho.metadata_chirho.keys() {
        validate_safe_token_chirho("metadata key", key_chirho)?;
    }
    if let Some(previous_chirho) = &input_chirho.previous_module_chirho {
        let _previous_module_chirho: DagModuleChirho =
            store_chirho::get_object_chirho(root_chirho, previous_chirho).with_context(|| {
                format!("previous module {} is not in the store", previous_chirho.0)
            })?;
    }
    let inputs_chirho = bind_ports_chirho(
        &input_chirho.input_bindings_chirho,
        &dag_chirho,
        &node_defs_chirho,
        ModuleBoundaryChirho::InputChirho,
    )?;
    let outputs_chirho = bind_ports_chirho(
        &input_chirho.output_bindings_chirho,
        &dag_chirho,
        &node_defs_chirho,
        ModuleBoundaryChirho::OutputChirho,
    )?;
    let module_chirho = DagModuleChirho {
        name_chirho: input_chirho.name_chirho,
        dag_chirho: input_chirho.dag_chirho,
        version_chirho: input_chirho.version_chirho,
        previous_module_chirho: input_chirho.previous_module_chirho,
        inputs_chirho,
        outputs_chirho,
        route_labels_chirho: input_chirho.route_labels_chirho,
        metadata_chirho: input_chirho.metadata_chirho,
    };
    validate_dag_module_chirho(root_chirho, &module_chirho)?;
    let module_hash_chirho = store_chirho::put_object_chirho(root_chirho, &module_chirho)?;
    Ok((module_chirho, module_hash_chirho))
}

pub fn load_dag_module_chirho(
    root_chirho: &Path,
    module_chirho: &HashChirho,
) -> Result<DagModuleChirho> {
    store_chirho::get_object_chirho(root_chirho, module_chirho)
        .with_context(|| format!("DagModuleChirho {} is not in the store", module_chirho.0))
}

pub fn validate_stored_dag_module_chirho(
    root_chirho: &Path,
    module_chirho: &HashChirho,
) -> Result<DagModuleChirho> {
    let module_obj_chirho = load_dag_module_chirho(root_chirho, module_chirho)?;
    validate_dag_module_chirho(root_chirho, &module_obj_chirho)?;
    Ok(module_obj_chirho)
}

pub fn build_dag_module_composition_chirho(
    root_chirho: &Path,
    input_chirho: DagModuleCompositionBuildInputChirho,
) -> Result<(DagModuleCompositionChirho, HashChirho)> {
    validate_safe_token_chirho("composition name", &input_chirho.name_chirho)?;
    validate_safe_token_chirho("composition version", &input_chirho.version_chirho)?;
    for key_chirho in input_chirho.metadata_chirho.keys() {
        validate_safe_token_chirho("metadata key", key_chirho)?;
    }
    let instances_chirho = composition_instances_chirho(&input_chirho.instances_chirho)?;
    let module_map_chirho = load_composition_modules_chirho(root_chirho, &instances_chirho)?;
    let wires_chirho = composition_wires_chirho(&input_chirho.wires_chirho, &module_map_chirho)?;
    let composed_dag_obj_chirho =
        expand_modules_to_dag_chirho(root_chirho, &instances_chirho, &wires_chirho)?;
    let composed_dag_chirho =
        store_chirho::put_object_chirho(root_chirho, &composed_dag_obj_chirho)?;
    let inputs_chirho = bind_composition_ports_chirho(
        &input_chirho.input_bindings_chirho,
        &module_map_chirho,
        &wires_chirho,
        ModuleBoundaryChirho::InputChirho,
    )?;
    let outputs_chirho = bind_composition_ports_chirho(
        &input_chirho.output_bindings_chirho,
        &module_map_chirho,
        &wires_chirho,
        ModuleBoundaryChirho::OutputChirho,
    )?;
    if outputs_chirho.is_empty() {
        bail!("DagModuleCompositionChirho needs at least one external output port");
    }
    let composition_chirho = DagModuleCompositionChirho {
        name_chirho: input_chirho.name_chirho,
        version_chirho: input_chirho.version_chirho,
        instances_chirho,
        wires_chirho,
        inputs_chirho,
        outputs_chirho,
        composed_dag_chirho,
        metadata_chirho: input_chirho.metadata_chirho,
    };
    validate_dag_module_composition_chirho(root_chirho, &composition_chirho)?;
    let composition_hash_chirho =
        store_chirho::put_object_chirho(root_chirho, &composition_chirho)?;
    Ok((composition_chirho, composition_hash_chirho))
}

pub fn load_dag_module_composition_chirho(
    root_chirho: &Path,
    composition_chirho: &HashChirho,
) -> Result<DagModuleCompositionChirho> {
    store_chirho::get_object_chirho(root_chirho, composition_chirho).with_context(|| {
        format!(
            "DagModuleCompositionChirho {} is not in the store",
            composition_chirho.0
        )
    })
}

pub fn validate_stored_dag_module_composition_chirho(
    root_chirho: &Path,
    composition_chirho: &HashChirho,
) -> Result<DagModuleCompositionChirho> {
    let composition_obj_chirho =
        load_dag_module_composition_chirho(root_chirho, composition_chirho)?;
    validate_dag_module_composition_chirho(root_chirho, &composition_obj_chirho)?;
    Ok(composition_obj_chirho)
}

pub fn validate_dag_module_composition_chirho(
    root_chirho: &Path,
    composition_chirho: &DagModuleCompositionChirho,
) -> Result<()> {
    validate_safe_token_chirho("composition name", &composition_chirho.name_chirho)?;
    validate_safe_token_chirho("composition version", &composition_chirho.version_chirho)?;
    if composition_chirho.outputs_chirho.is_empty() {
        bail!("DagModuleCompositionChirho needs at least one external output port");
    }
    let module_map_chirho =
        load_composition_modules_chirho(root_chirho, &composition_chirho.instances_chirho)?;
    let normalized_wires_chirho =
        normalize_composition_wires_chirho(&composition_chirho.wires_chirho, &module_map_chirho)?;
    if normalized_wires_chirho != composition_chirho.wires_chirho {
        bail!("composition wires are not in canonical validated form");
    }
    validate_composition_ports_chirho(
        &composition_chirho.inputs_chirho,
        &module_map_chirho,
        &composition_chirho.wires_chirho,
        ModuleBoundaryChirho::InputChirho,
    )?;
    validate_composition_ports_chirho(
        &composition_chirho.outputs_chirho,
        &module_map_chirho,
        &composition_chirho.wires_chirho,
        ModuleBoundaryChirho::OutputChirho,
    )?;
    for key_chirho in composition_chirho.metadata_chirho.keys() {
        validate_safe_token_chirho("metadata key", key_chirho)?;
    }
    let expanded_chirho = expand_modules_to_dag_chirho(
        root_chirho,
        &composition_chirho.instances_chirho,
        &composition_chirho.wires_chirho,
    )?;
    let expected_dag_hash_chirho = store_chirho::hash_object_chirho(&expanded_chirho)?;
    if expected_dag_hash_chirho != composition_chirho.composed_dag_chirho {
        bail!(
            "composition composed_dag_chirho {} does not match recomputed {}",
            composition_chirho.composed_dag_chirho.0,
            expected_dag_hash_chirho.0
        );
    }
    let stored_dag_chirho: DagChirho =
        store_chirho::get_object_chirho(root_chirho, &composition_chirho.composed_dag_chirho)
            .with_context(|| {
                format!(
                    "composed DagChirho {} is missing",
                    composition_chirho.composed_dag_chirho.0
                )
            })?;
    if stored_dag_chirho != expanded_chirho {
        bail!("stored composed DagChirho does not match the module expansion");
    }
    Ok(())
}

/// An operator's run of a stored composition (the CLI's): its private values join no account.
pub fn run_dag_module_composition_chirho(
    root_chirho: &Path,
    composition_chirho: &HashChirho,
    input_bytes_chirho: &[u8],
) -> Result<DagModuleCompositionRunReportChirho> {
    let composition_obj_chirho =
        validate_stored_dag_module_composition_chirho(root_chirho, composition_chirho)?;
    let dag_obj_chirho: DagChirho =
        store_chirho::get_object_chirho(root_chirho, &composition_obj_chirho.composed_dag_chirho)?;
    let dag_report_chirho =
        dag_chirho::run_dag_as_operator_chirho(root_chirho, &dag_obj_chirho, input_bytes_chirho)?;
    let node_to_instance_chirho = composition_node_instance_map_chirho(
        root_chirho,
        &composition_obj_chirho.instances_chirho,
    )?;
    let mut instance_runs_chirho: BTreeMap<String, DagModuleInstanceRunChirho> =
        composition_obj_chirho
            .instances_chirho
            .iter()
            .map(|instance_chirho| {
                (
                    instance_chirho.instance_chirho.clone(),
                    DagModuleInstanceRunChirho {
                        instance_chirho: instance_chirho.instance_chirho.clone(),
                        module_chirho: instance_chirho.module_chirho.clone(),
                        node_runs_chirho: Vec::new(),
                    },
                )
            })
            .collect();
    for node_run_chirho in &dag_report_chirho.node_runs_chirho {
        let instance_chirho = node_to_instance_chirho
            .get(&node_run_chirho.node_chirho)
            .ok_or_else(|| {
                anyhow!(
                    "run node {} is not owned by any composition instance",
                    node_run_chirho.node_chirho.0
                )
            })?;
        instance_runs_chirho
            .get_mut(instance_chirho)
            .expect("instance map initialized")
            .node_runs_chirho
            .push(node_run_chirho.clone());
    }
    Ok(DagModuleCompositionRunReportChirho {
        composition_chirho: composition_obj_chirho,
        dag_report_chirho,
        instance_runs_chirho: instance_runs_chirho.into_values().collect(),
    })
}

pub fn validate_dag_module_chirho(
    root_chirho: &Path,
    module_chirho: &DagModuleChirho,
) -> Result<()> {
    validate_safe_token_chirho("module name", &module_chirho.name_chirho)?;
    validate_safe_token_chirho("module version", &module_chirho.version_chirho)?;
    let dag_chirho: DagChirho =
        store_chirho::get_object_chirho(root_chirho, &module_chirho.dag_chirho).with_context(
            || {
                format!(
                    "wrapped DagChirho {} is missing",
                    module_chirho.dag_chirho.0
                )
            },
        )?;
    let node_defs_chirho = load_node_defs_chirho(root_chirho, &dag_chirho)?;
    if module_chirho.outputs_chirho.is_empty() {
        bail!("DagModuleChirho needs at least one external output port");
    }
    validate_bound_ports_chirho(
        &module_chirho.inputs_chirho,
        &dag_chirho,
        &node_defs_chirho,
        ModuleBoundaryChirho::InputChirho,
    )?;
    validate_bound_ports_chirho(
        &module_chirho.outputs_chirho,
        &dag_chirho,
        &node_defs_chirho,
        ModuleBoundaryChirho::OutputChirho,
    )?;
    for route_chirho in &module_chirho.route_labels_chirho {
        validate_safe_token_chirho("route label", route_chirho)?;
    }
    for key_chirho in module_chirho.metadata_chirho.keys() {
        validate_safe_token_chirho("metadata key", key_chirho)?;
    }
    if let Some(previous_chirho) = &module_chirho.previous_module_chirho {
        let _previous_module_chirho: DagModuleChirho =
            store_chirho::get_object_chirho(root_chirho, previous_chirho).with_context(|| {
                format!("previous module {} is not in the store", previous_chirho.0)
            })?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModuleBoundaryChirho {
    InputChirho,
    OutputChirho,
}

fn composition_instances_chirho(
    instances_chirho: &[DagModuleInstanceInputChirho],
) -> Result<Vec<DagModuleInstanceChirho>> {
    if instances_chirho.is_empty() {
        bail!("DagModuleCompositionChirho needs at least one module instance");
    }
    let mut seen_chirho = BTreeSet::new();
    let mut out_chirho = Vec::new();
    for instance_chirho in instances_chirho {
        validate_safe_token_chirho("module instance", &instance_chirho.instance_chirho)?;
        if !seen_chirho.insert(instance_chirho.instance_chirho.clone()) {
            bail!(
                "duplicate module instance '{}'",
                instance_chirho.instance_chirho
            );
        }
        out_chirho.push(DagModuleInstanceChirho {
            instance_chirho: instance_chirho.instance_chirho.clone(),
            module_chirho: instance_chirho.module_chirho.clone(),
        });
    }
    Ok(out_chirho)
}

fn load_composition_modules_chirho(
    root_chirho: &Path,
    instances_chirho: &[DagModuleInstanceChirho],
) -> Result<BTreeMap<String, DagModuleChirho>> {
    let mut modules_chirho = BTreeMap::new();
    for instance_chirho in instances_chirho {
        validate_safe_token_chirho("module instance", &instance_chirho.instance_chirho)?;
        if modules_chirho.contains_key(&instance_chirho.instance_chirho) {
            bail!(
                "duplicate module instance '{}'",
                instance_chirho.instance_chirho
            );
        }
        let module_chirho =
            validate_stored_dag_module_chirho(root_chirho, &instance_chirho.module_chirho)
                .with_context(|| {
                    format!(
                        "validate module instance '{}' ({})",
                        instance_chirho.instance_chirho, instance_chirho.module_chirho.0
                    )
                })?;
        modules_chirho.insert(instance_chirho.instance_chirho.clone(), module_chirho);
    }
    if modules_chirho.is_empty() {
        bail!("DagModuleCompositionChirho needs at least one module instance");
    }
    Ok(modules_chirho)
}

fn composition_wires_chirho(
    wires_chirho: &[DagModuleWireInputChirho],
    modules_chirho: &BTreeMap<String, DagModuleChirho>,
) -> Result<Vec<DagModuleWireChirho>> {
    let wires_chirho: Vec<DagModuleWireChirho> = wires_chirho
        .iter()
        .map(|wire_chirho| DagModuleWireChirho {
            from_instance_chirho: wire_chirho.from_instance_chirho.clone(),
            from_port_chirho: wire_chirho.from_port_chirho.clone(),
            to_instance_chirho: wire_chirho.to_instance_chirho.clone(),
            to_port_chirho: wire_chirho.to_port_chirho.clone(),
        })
        .collect();
    normalize_composition_wires_chirho(&wires_chirho, modules_chirho)
}

fn normalize_composition_wires_chirho(
    wires_chirho: &[DagModuleWireChirho],
    modules_chirho: &BTreeMap<String, DagModuleChirho>,
) -> Result<Vec<DagModuleWireChirho>> {
    let mut out_chirho = Vec::new();
    let mut driven_inputs_chirho = BTreeSet::new();
    for wire_chirho in wires_chirho {
        validate_safe_token_chirho("from instance", &wire_chirho.from_instance_chirho)?;
        validate_safe_token_chirho("from port", &wire_chirho.from_port_chirho)?;
        validate_safe_token_chirho("to instance", &wire_chirho.to_instance_chirho)?;
        validate_safe_token_chirho("to port", &wire_chirho.to_port_chirho)?;
        if wire_chirho.from_instance_chirho == wire_chirho.to_instance_chirho {
            bail!("module wire cannot connect an instance to itself");
        }
        let from_module_chirho = modules_chirho
            .get(&wire_chirho.from_instance_chirho)
            .ok_or_else(|| {
                anyhow!(
                    "wire from unknown instance '{}'",
                    wire_chirho.from_instance_chirho
                )
            })?;
        let to_module_chirho = modules_chirho
            .get(&wire_chirho.to_instance_chirho)
            .ok_or_else(|| {
                anyhow!(
                    "wire to unknown instance '{}'",
                    wire_chirho.to_instance_chirho
                )
            })?;
        let from_port_chirho = module_port_chirho(
            from_module_chirho,
            &wire_chirho.from_port_chirho,
            ModuleBoundaryChirho::OutputChirho,
        )?;
        let to_port_chirho = module_port_chirho(
            to_module_chirho,
            &wire_chirho.to_port_chirho,
            ModuleBoundaryChirho::InputChirho,
        )?;
        if from_port_chirho.public_port_chirho.schema_chirho
            != to_port_chirho.public_port_chirho.schema_chirho
        {
            bail!(
                "module wire schema mismatch: {}.{}={} -> {}.{}={}",
                wire_chirho.from_instance_chirho,
                wire_chirho.from_port_chirho,
                from_port_chirho.public_port_chirho.schema_chirho.0,
                wire_chirho.to_instance_chirho,
                wire_chirho.to_port_chirho,
                to_port_chirho.public_port_chirho.schema_chirho.0
            );
        }
        if !driven_inputs_chirho.insert((
            wire_chirho.to_instance_chirho.clone(),
            wire_chirho.to_port_chirho.clone(),
        )) {
            bail!(
                "module input {}.{} is driven more than once",
                wire_chirho.to_instance_chirho,
                wire_chirho.to_port_chirho
            );
        }
        out_chirho.push(wire_chirho.clone());
    }
    Ok(out_chirho)
}

fn expand_modules_to_dag_chirho(
    root_chirho: &Path,
    instances_chirho: &[DagModuleInstanceChirho],
    wires_chirho: &[DagModuleWireChirho],
) -> Result<DagChirho> {
    let modules_chirho = load_composition_modules_chirho(root_chirho, instances_chirho)?;
    let mut nodes_chirho = Vec::new();
    let mut edges_chirho = Vec::new();
    let mut node_owner_chirho: BTreeMap<HashChirho, String> = BTreeMap::new();
    for instance_chirho in instances_chirho {
        let module_chirho = modules_chirho
            .get(&instance_chirho.instance_chirho)
            .expect("loaded above");
        let dag_chirho: DagChirho =
            store_chirho::get_object_chirho(root_chirho, &module_chirho.dag_chirho)?;
        for node_chirho in &dag_chirho.nodes_chirho {
            if let Some(owner_chirho) = node_owner_chirho
                .insert(node_chirho.clone(), instance_chirho.instance_chirho.clone())
            {
                bail!(
                    "node {} appears in both module instances '{}' and '{}'; expansion requires disjoint node identities",
                    node_chirho.0,
                    owner_chirho,
                    instance_chirho.instance_chirho
                );
            }
            nodes_chirho.push(node_chirho.clone());
        }
        edges_chirho.extend(dag_chirho.edges_chirho);
    }
    for wire_chirho in normalize_composition_wires_chirho(wires_chirho, &modules_chirho)? {
        let from_module_chirho = modules_chirho
            .get(&wire_chirho.from_instance_chirho)
            .expect("wire validated");
        let to_module_chirho = modules_chirho
            .get(&wire_chirho.to_instance_chirho)
            .expect("wire validated");
        let from_port_chirho = module_port_chirho(
            from_module_chirho,
            &wire_chirho.from_port_chirho,
            ModuleBoundaryChirho::OutputChirho,
        )?;
        let to_port_chirho = module_port_chirho(
            to_module_chirho,
            &wire_chirho.to_port_chirho,
            ModuleBoundaryChirho::InputChirho,
        )?;
        edges_chirho.push(EdgeChirho {
            from_node_chirho: from_port_chirho.node_chirho.clone(),
            from_port_chirho: from_port_chirho.node_port_chirho.clone(),
            to_node_chirho: to_port_chirho.node_chirho.clone(),
            to_port_chirho: to_port_chirho.node_port_chirho.clone(),
            privacy_chirho: None,
        });
    }
    let dag_chirho = DagChirho {
        nodes_chirho,
        edges_chirho,
    };
    load_node_defs_chirho(root_chirho, &dag_chirho)?;
    assert_dag_acyclic_chirho(&dag_chirho)?;
    Ok(dag_chirho)
}

fn bind_composition_ports_chirho(
    bindings_chirho: &[DagModuleCompositionBindingInputChirho],
    modules_chirho: &BTreeMap<String, DagModuleChirho>,
    wires_chirho: &[DagModuleWireChirho],
    boundary_chirho: ModuleBoundaryChirho,
) -> Result<Vec<DagModuleCompositionPortChirho>> {
    let mut ports_chirho = Vec::new();
    let mut seen_chirho = BTreeSet::new();
    for binding_chirho in bindings_chirho {
        validate_safe_token_chirho(
            "composition public port",
            &binding_chirho.public_name_chirho,
        )?;
        validate_safe_token_chirho("composition instance", &binding_chirho.instance_chirho)?;
        validate_safe_token_chirho(
            "composition module port",
            &binding_chirho.module_port_chirho,
        )?;
        if !seen_chirho.insert(binding_chirho.public_name_chirho.clone()) {
            bail!(
                "duplicate composition public port '{}'",
                binding_chirho.public_name_chirho
            );
        }
        let module_chirho = modules_chirho
            .get(&binding_chirho.instance_chirho)
            .ok_or_else(|| {
                anyhow!(
                    "composition port references unknown instance '{}'",
                    binding_chirho.instance_chirho
                )
            })?;
        let module_port_chirho = module_port_chirho(
            module_chirho,
            &binding_chirho.module_port_chirho,
            boundary_chirho,
        )?;
        assert_composition_boundary_port_chirho(
            &binding_chirho.instance_chirho,
            &binding_chirho.module_port_chirho,
            wires_chirho,
            boundary_chirho,
        )?;
        ports_chirho.push(DagModuleCompositionPortChirho {
            public_port_chirho: PortChirho {
                name_chirho: binding_chirho.public_name_chirho.clone(),
                schema_chirho: module_port_chirho.public_port_chirho.schema_chirho.clone(),
            },
            instance_chirho: binding_chirho.instance_chirho.clone(),
            module_port_chirho: binding_chirho.module_port_chirho.clone(),
        });
    }
    Ok(ports_chirho)
}

fn validate_composition_ports_chirho(
    ports_chirho: &[DagModuleCompositionPortChirho],
    modules_chirho: &BTreeMap<String, DagModuleChirho>,
    wires_chirho: &[DagModuleWireChirho],
    boundary_chirho: ModuleBoundaryChirho,
) -> Result<()> {
    let mut seen_chirho = BTreeSet::new();
    for port_chirho in ports_chirho {
        validate_safe_token_chirho(
            "composition public port",
            &port_chirho.public_port_chirho.name_chirho,
        )?;
        validate_safe_token_chirho("composition instance", &port_chirho.instance_chirho)?;
        validate_safe_token_chirho("composition module port", &port_chirho.module_port_chirho)?;
        if !seen_chirho.insert(port_chirho.public_port_chirho.name_chirho.clone()) {
            bail!(
                "duplicate composition public port '{}'",
                port_chirho.public_port_chirho.name_chirho
            );
        }
        let module_chirho = modules_chirho
            .get(&port_chirho.instance_chirho)
            .ok_or_else(|| {
                anyhow!(
                    "composition port references unknown instance '{}'",
                    port_chirho.instance_chirho
                )
            })?;
        let module_port_chirho = module_port_chirho(
            module_chirho,
            &port_chirho.module_port_chirho,
            boundary_chirho,
        )?;
        assert_composition_boundary_port_chirho(
            &port_chirho.instance_chirho,
            &port_chirho.module_port_chirho,
            wires_chirho,
            boundary_chirho,
        )?;
        if module_port_chirho.public_port_chirho.schema_chirho
            != port_chirho.public_port_chirho.schema_chirho
        {
            bail!(
                "composition public port '{}' schema {} does not match module port '{}.{}' schema {}",
                port_chirho.public_port_chirho.name_chirho,
                port_chirho.public_port_chirho.schema_chirho.0,
                port_chirho.instance_chirho,
                port_chirho.module_port_chirho,
                module_port_chirho.public_port_chirho.schema_chirho.0
            );
        }
    }
    Ok(())
}

fn assert_composition_boundary_port_chirho(
    instance_chirho: &str,
    port_chirho: &str,
    wires_chirho: &[DagModuleWireChirho],
    boundary_chirho: ModuleBoundaryChirho,
) -> Result<()> {
    match boundary_chirho {
        ModuleBoundaryChirho::InputChirho => {
            if wires_chirho.iter().any(|wire_chirho| {
                wire_chirho.to_instance_chirho == instance_chirho
                    && wire_chirho.to_port_chirho == port_chirho
            }) {
                bail!(
                    "composition input {}.{} is already driven by a module wire",
                    instance_chirho,
                    port_chirho
                );
            }
        }
        ModuleBoundaryChirho::OutputChirho => {
            if wires_chirho.iter().any(|wire_chirho| {
                wire_chirho.from_instance_chirho == instance_chirho
                    && wire_chirho.from_port_chirho == port_chirho
            }) {
                bail!(
                    "composition output {}.{} is already consumed by a module wire",
                    instance_chirho,
                    port_chirho
                );
            }
        }
    }
    Ok(())
}

fn module_port_chirho<'a>(
    module_chirho: &'a DagModuleChirho,
    port_chirho: &str,
    boundary_chirho: ModuleBoundaryChirho,
) -> Result<&'a DagModulePortChirho> {
    let ports_chirho = match boundary_chirho {
        ModuleBoundaryChirho::InputChirho => &module_chirho.inputs_chirho,
        ModuleBoundaryChirho::OutputChirho => &module_chirho.outputs_chirho,
    };
    ports_chirho
        .iter()
        .find(|candidate_chirho| candidate_chirho.public_port_chirho.name_chirho == port_chirho)
        .ok_or_else(|| {
            anyhow!(
                "module '{}' has no {:?} port '{}'",
                module_chirho.name_chirho,
                boundary_chirho,
                port_chirho
            )
        })
}

fn composition_node_instance_map_chirho(
    root_chirho: &Path,
    instances_chirho: &[DagModuleInstanceChirho],
) -> Result<BTreeMap<HashChirho, String>> {
    let mut out_chirho = BTreeMap::new();
    for instance_chirho in instances_chirho {
        let module_chirho =
            validate_stored_dag_module_chirho(root_chirho, &instance_chirho.module_chirho)?;
        let dag_chirho: DagChirho =
            store_chirho::get_object_chirho(root_chirho, &module_chirho.dag_chirho)?;
        for node_chirho in dag_chirho.nodes_chirho {
            if let Some(previous_chirho) =
                out_chirho.insert(node_chirho.clone(), instance_chirho.instance_chirho.clone())
            {
                bail!(
                    "node {} appears in both module instances '{}' and '{}'",
                    node_chirho.0,
                    previous_chirho,
                    instance_chirho.instance_chirho
                );
            }
        }
    }
    Ok(out_chirho)
}

fn assert_dag_acyclic_chirho(dag_chirho: &DagChirho) -> Result<()> {
    let mut indegree_chirho: BTreeMap<HashChirho, usize> = BTreeMap::new();
    for node_chirho in &dag_chirho.nodes_chirho {
        indegree_chirho.entry(node_chirho.clone()).or_insert(0);
    }
    for edge_chirho in &dag_chirho.edges_chirho {
        *indegree_chirho
            .entry(edge_chirho.to_node_chirho.clone())
            .or_insert(0) += 1;
    }
    let mut queue_chirho: VecDeque<HashChirho> = indegree_chirho
        .iter()
        .filter_map(|(node_chirho, degree_chirho)| {
            if *degree_chirho == 0 {
                Some(node_chirho.clone())
            } else {
                None
            }
        })
        .collect();
    let mut seen_chirho = 0_usize;
    while let Some(node_chirho) = queue_chirho.pop_front() {
        seen_chirho += 1;
        for edge_chirho in dag_chirho
            .edges_chirho
            .iter()
            .filter(|edge_chirho| edge_chirho.from_node_chirho == node_chirho)
        {
            if let Some(degree_chirho) = indegree_chirho.get_mut(&edge_chirho.to_node_chirho) {
                *degree_chirho -= 1;
                if *degree_chirho == 0 {
                    queue_chirho.push_back(edge_chirho.to_node_chirho.clone());
                }
            }
        }
    }
    if seen_chirho != indegree_chirho.len() {
        bail!("module composition expands to a cyclic DagChirho");
    }
    Ok(())
}

fn bind_ports_chirho(
    bindings_chirho: &[DagModuleBindingInputChirho],
    dag_chirho: &DagChirho,
    node_defs_chirho: &BTreeMap<HashChirho, NodeDefChirho>,
    boundary_chirho: ModuleBoundaryChirho,
) -> Result<Vec<DagModulePortChirho>> {
    let mut ports_chirho = Vec::new();
    let mut seen_chirho = BTreeSet::new();
    for binding_chirho in bindings_chirho {
        validate_safe_token_chirho("public port", &binding_chirho.public_name_chirho)?;
        validate_safe_token_chirho("node port", &binding_chirho.node_port_chirho)?;
        if !seen_chirho.insert(binding_chirho.public_name_chirho.clone()) {
            bail!(
                "duplicate public module port '{}'",
                binding_chirho.public_name_chirho
            );
        }
        let node_def_chirho = node_defs_chirho
            .get(&binding_chirho.node_chirho)
            .ok_or_else(|| {
                anyhow!(
                    "node {} is not in wrapped DAG",
                    binding_chirho.node_chirho.0
                )
            })?;
        let node_port_chirho = find_node_port_chirho(
            node_def_chirho,
            &binding_chirho.node_port_chirho,
            boundary_chirho,
        )?;
        assert_boundary_port_chirho(
            dag_chirho,
            &binding_chirho.node_chirho,
            &binding_chirho.node_port_chirho,
            boundary_chirho,
        )?;
        ports_chirho.push(DagModulePortChirho {
            public_port_chirho: PortChirho {
                name_chirho: binding_chirho.public_name_chirho.clone(),
                schema_chirho: node_port_chirho.schema_chirho.clone(),
            },
            node_chirho: binding_chirho.node_chirho.clone(),
            node_port_chirho: binding_chirho.node_port_chirho.clone(),
        });
    }
    Ok(ports_chirho)
}

fn validate_bound_ports_chirho(
    ports_chirho: &[DagModulePortChirho],
    dag_chirho: &DagChirho,
    node_defs_chirho: &BTreeMap<HashChirho, NodeDefChirho>,
    boundary_chirho: ModuleBoundaryChirho,
) -> Result<()> {
    let mut seen_chirho = BTreeSet::new();
    for port_chirho in ports_chirho {
        validate_safe_token_chirho("public port", &port_chirho.public_port_chirho.name_chirho)?;
        validate_safe_token_chirho("node port", &port_chirho.node_port_chirho)?;
        if !seen_chirho.insert(port_chirho.public_port_chirho.name_chirho.clone()) {
            bail!(
                "duplicate public module port '{}'",
                port_chirho.public_port_chirho.name_chirho
            );
        }
        let node_def_chirho = node_defs_chirho
            .get(&port_chirho.node_chirho)
            .ok_or_else(|| anyhow!("node {} is not in wrapped DAG", port_chirho.node_chirho.0))?;
        let node_port_chirho = find_node_port_chirho(
            node_def_chirho,
            &port_chirho.node_port_chirho,
            boundary_chirho,
        )?;
        assert_boundary_port_chirho(
            dag_chirho,
            &port_chirho.node_chirho,
            &port_chirho.node_port_chirho,
            boundary_chirho,
        )?;
        if node_port_chirho.schema_chirho != port_chirho.public_port_chirho.schema_chirho {
            bail!(
                "module port '{}' schema {} does not match node port '{}' schema {}",
                port_chirho.public_port_chirho.name_chirho,
                port_chirho.public_port_chirho.schema_chirho.0,
                port_chirho.node_port_chirho,
                node_port_chirho.schema_chirho.0
            );
        }
    }
    Ok(())
}

fn assert_boundary_port_chirho(
    dag_chirho: &DagChirho,
    node_chirho: &HashChirho,
    port_chirho: &str,
    boundary_chirho: ModuleBoundaryChirho,
) -> Result<()> {
    match boundary_chirho {
        ModuleBoundaryChirho::InputChirho => {
            if dag_chirho.edges_chirho.iter().any(|edge_chirho| {
                &edge_chirho.to_node_chirho == node_chirho
                    && edge_chirho.to_port_chirho == port_chirho
            }) {
                bail!(
                    "module input {}.{} is already driven by an internal edge",
                    node_chirho.0,
                    port_chirho
                );
            }
        }
        ModuleBoundaryChirho::OutputChirho => {
            if dag_chirho.edges_chirho.iter().any(|edge_chirho| {
                &edge_chirho.from_node_chirho == node_chirho
                    && edge_chirho.from_port_chirho == port_chirho
            }) {
                bail!(
                    "module output {}.{} is already consumed by an internal edge",
                    node_chirho.0,
                    port_chirho
                );
            }
        }
    }
    Ok(())
}

fn find_node_port_chirho<'a>(
    node_def_chirho: &'a NodeDefChirho,
    port_chirho: &str,
    boundary_chirho: ModuleBoundaryChirho,
) -> Result<&'a PortChirho> {
    let ports_chirho = match boundary_chirho {
        ModuleBoundaryChirho::InputChirho => &node_def_chirho.inputs_chirho,
        ModuleBoundaryChirho::OutputChirho => &node_def_chirho.outputs_chirho,
    };
    ports_chirho
        .iter()
        .find(|candidate_chirho| candidate_chirho.name_chirho == port_chirho)
        .ok_or_else(|| {
            anyhow!(
                "node '{}' has no {:?} port '{}'",
                node_def_chirho.name_chirho,
                boundary_chirho,
                port_chirho
            )
        })
}

fn load_node_defs_chirho(
    root_chirho: &Path,
    dag_chirho: &DagChirho,
) -> Result<BTreeMap<HashChirho, NodeDefChirho>> {
    let mut defs_chirho = BTreeMap::new();
    for node_chirho in &dag_chirho.nodes_chirho {
        let def_chirho: NodeDefChirho =
            store_chirho::get_object_chirho(root_chirho, node_chirho)
                .with_context(|| format!("DAG node {} is not in the store", node_chirho.0))?;
        defs_chirho.insert(node_chirho.clone(), def_chirho);
    }
    for edge_chirho in &dag_chirho.edges_chirho {
        if !defs_chirho.contains_key(&edge_chirho.from_node_chirho) {
            bail!(
                "DAG edge references missing from_node {}",
                edge_chirho.from_node_chirho.0
            );
        }
        if !defs_chirho.contains_key(&edge_chirho.to_node_chirho) {
            bail!(
                "DAG edge references missing to_node {}",
                edge_chirho.to_node_chirho.0
            );
        }
        let from_def_chirho = defs_chirho
            .get(&edge_chirho.from_node_chirho)
            .expect("checked above");
        let to_def_chirho = defs_chirho
            .get(&edge_chirho.to_node_chirho)
            .expect("checked above");
        let from_port_chirho = find_named_port_chirho(
            &from_def_chirho.outputs_chirho,
            &edge_chirho.from_port_chirho,
        )
        .ok_or_else(|| {
            anyhow!(
                "edge from port '{}' missing on node '{}'",
                edge_chirho.from_port_chirho,
                from_def_chirho.name_chirho
            )
        })?;
        let to_port_chirho =
            find_named_port_chirho(&to_def_chirho.inputs_chirho, &edge_chirho.to_port_chirho)
                .ok_or_else(|| {
                    anyhow!(
                        "edge to port '{}' missing on node '{}'",
                        edge_chirho.to_port_chirho,
                        to_def_chirho.name_chirho
                    )
                })?;
        if from_port_chirho.schema_chirho != to_port_chirho.schema_chirho {
            bail!(
                "edge schema mismatch: {}.{}={} -> {}.{}={}",
                from_def_chirho.name_chirho,
                edge_chirho.from_port_chirho,
                from_port_chirho.schema_chirho.0,
                to_def_chirho.name_chirho,
                edge_chirho.to_port_chirho,
                to_port_chirho.schema_chirho.0
            );
        }
    }
    Ok(defs_chirho)
}

fn find_named_port_chirho<'a>(
    ports_chirho: &'a [PortChirho],
    name_chirho: &str,
) -> Option<&'a PortChirho> {
    ports_chirho
        .iter()
        .find(|port_chirho| port_chirho.name_chirho == name_chirho)
}

fn validate_safe_token_chirho(name_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.trim().is_empty()
        || value_chirho.len() > 128
        || !value_chirho.chars().all(|ch_chirho| {
            ch_chirho.is_ascii_alphanumeric() || matches!(ch_chirho, '-' | '_' | '/' | ':' | '.')
        })
    {
        bail!("{name_chirho} must be a short opaque token");
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::model_chirho::EdgeChirho;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_root_chirho() -> std::path::PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!("cairn-dag-module-test-{nanos_chirho}-{n_chirho}"))
    }

    fn node_chirho(
        root_chirho: &Path,
        name_chirho: &str,
        input_schema_chirho: HashChirho,
        output_schema_chirho: HashChirho,
    ) -> HashChirho {
        let wasm_chirho =
            crate::cas_chirho::add_chirho(root_chirho, name_chirho.as_bytes()).unwrap();
        let node_chirho = NodeDefChirho {
            name_chirho: name_chirho.to_string(),
            impl_wasm_chirho: wasm_chirho,
            entry_chirho: "node_chirho".to_string(),
            inputs_chirho: vec![PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: input_schema_chirho,
            }],
            outputs_chirho: vec![PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho: output_schema_chirho,
            }],
            capabilities_chirho: vec![],
            fuel_limit_chirho: 1_000_000,
            ..Default::default()
        };
        store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap()
    }

    fn runnable_node_chirho(
        root_chirho: &Path,
        name_chirho: &str,
        wat_chirho: &str,
        entry_chirho: &str,
        schema_chirho: HashChirho,
    ) -> HashChirho {
        let wasm_chirho =
            crate::cas_chirho::add_chirho(root_chirho, wat_chirho.as_bytes()).unwrap();
        let node_chirho = NodeDefChirho {
            name_chirho: name_chirho.to_string(),
            impl_wasm_chirho: wasm_chirho,
            entry_chirho: entry_chirho.to_string(),
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
        store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap()
    }

    fn single_node_module_chirho(
        root_chirho: &Path,
        name_chirho: &str,
        node_chirho: HashChirho,
    ) -> (DagModuleChirho, HashChirho, HashChirho) {
        let dag_chirho = DagChirho {
            nodes_chirho: vec![node_chirho.clone()],
            edges_chirho: vec![],
        };
        let dag_hash_chirho = store_chirho::put_object_chirho(root_chirho, &dag_chirho).unwrap();
        let (module_chirho, module_hash_chirho) = build_dag_module_chirho(
            root_chirho,
            DagModuleBuildInputChirho {
                name_chirho: name_chirho.to_string(),
                dag_chirho: dag_hash_chirho.clone(),
                version_chirho: "v1".to_string(),
                previous_module_chirho: None,
                input_bindings_chirho: vec![DagModuleBindingInputChirho {
                    public_name_chirho: "request".to_string(),
                    node_chirho: node_chirho.clone(),
                    node_port_chirho: "in".to_string(),
                }],
                output_bindings_chirho: vec![DagModuleBindingInputChirho {
                    public_name_chirho: "response".to_string(),
                    node_chirho,
                    node_port_chirho: "out".to_string(),
                }],
                route_labels_chirho: vec![],
                metadata_chirho: BTreeMap::new(),
            },
        )
        .unwrap();
        (module_chirho, module_hash_chirho, dag_hash_chirho)
    }

    #[test]
    fn dag_module_wraps_dag_without_changing_dag_hash_chirho() {
        let root_chirho = tmp_root_chirho();
        let bytes_schema_chirho = crate::cas_chirho::add_chirho(&root_chirho, b"bytes").unwrap();
        let first_chirho = node_chirho(
            &root_chirho,
            "first_chirho",
            bytes_schema_chirho.clone(),
            bytes_schema_chirho.clone(),
        );
        let second_chirho = node_chirho(
            &root_chirho,
            "second_chirho",
            bytes_schema_chirho.clone(),
            bytes_schema_chirho,
        );
        let dag_chirho = DagChirho {
            nodes_chirho: vec![first_chirho.clone(), second_chirho.clone()],
            edges_chirho: vec![EdgeChirho {
                from_node_chirho: first_chirho.clone(),
                from_port_chirho: "out".to_string(),
                to_node_chirho: second_chirho.clone(),
                to_port_chirho: "in".to_string(),
                privacy_chirho: None,
            }],
        };
        let dag_hash_before_chirho =
            store_chirho::put_object_chirho(&root_chirho, &dag_chirho).unwrap();

        let (module_chirho, module_hash_chirho) = build_dag_module_chirho(
            &root_chirho,
            DagModuleBuildInputChirho {
                name_chirho: "text-pipeline-chirho".to_string(),
                dag_chirho: dag_hash_before_chirho.clone(),
                version_chirho: "v1".to_string(),
                previous_module_chirho: None,
                input_bindings_chirho: vec![DagModuleBindingInputChirho {
                    public_name_chirho: "request".to_string(),
                    node_chirho: first_chirho.clone(),
                    node_port_chirho: "in".to_string(),
                }],
                output_bindings_chirho: vec![DagModuleBindingInputChirho {
                    public_name_chirho: "response".to_string(),
                    node_chirho: second_chirho,
                    node_port_chirho: "out".to_string(),
                }],
                route_labels_chirho: vec!["support-chirho".to_string()],
                metadata_chirho: BTreeMap::from([(
                    "profile_chirho".to_string(),
                    "server-chirho".to_string(),
                )]),
            },
        )
        .unwrap();

        assert_eq!(module_chirho.dag_chirho, dag_hash_before_chirho);
        assert_ne!(module_hash_chirho, dag_hash_before_chirho);
        assert_eq!(
            store_chirho::hash_object_chirho(&dag_chirho).unwrap(),
            dag_hash_before_chirho
        );
        let loaded_chirho =
            validate_stored_dag_module_chirho(&root_chirho, &module_hash_chirho).unwrap();
        assert_eq!(loaded_chirho, module_chirho);
        assert_eq!(
            loaded_chirho.inputs_chirho[0]
                .public_port_chirho
                .schema_chirho,
            loaded_chirho.outputs_chirho[0]
                .public_port_chirho
                .schema_chirho
        );
        let internal_output_chirho = build_dag_module_chirho(
            &root_chirho,
            DagModuleBuildInputChirho {
                name_chirho: "bad-boundary-chirho".to_string(),
                dag_chirho: dag_hash_before_chirho,
                version_chirho: "v1".to_string(),
                previous_module_chirho: None,
                input_bindings_chirho: vec![],
                output_bindings_chirho: vec![DagModuleBindingInputChirho {
                    public_name_chirho: "internal".to_string(),
                    node_chirho: first_chirho,
                    node_port_chirho: "out".to_string(),
                }],
                route_labels_chirho: vec![],
                metadata_chirho: BTreeMap::new(),
            },
        );
        assert!(internal_output_chirho.is_err());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn dag_module_rejects_bad_port_and_schema_chirho() {
        let root_chirho = tmp_root_chirho();
        let bytes_schema_chirho = crate::cas_chirho::add_chirho(&root_chirho, b"bytes").unwrap();
        let json_schema_chirho = crate::cas_chirho::add_chirho(&root_chirho, b"json").unwrap();
        let node_hash_chirho = node_chirho(
            &root_chirho,
            "node_chirho",
            bytes_schema_chirho.clone(),
            bytes_schema_chirho.clone(),
        );
        let dag_hash_chirho = store_chirho::put_object_chirho(
            &root_chirho,
            &DagChirho {
                nodes_chirho: vec![node_hash_chirho.clone()],
                edges_chirho: vec![],
            },
        )
        .unwrap();

        let bad_port_chirho = build_dag_module_chirho(
            &root_chirho,
            DagModuleBuildInputChirho {
                name_chirho: "bad-chirho".to_string(),
                dag_chirho: dag_hash_chirho.clone(),
                version_chirho: "v1".to_string(),
                previous_module_chirho: None,
                input_bindings_chirho: vec![DagModuleBindingInputChirho {
                    public_name_chirho: "request".to_string(),
                    node_chirho: node_hash_chirho.clone(),
                    node_port_chirho: "missing".to_string(),
                }],
                output_bindings_chirho: vec![],
                route_labels_chirho: vec![],
                metadata_chirho: BTreeMap::new(),
            },
        );
        assert!(bad_port_chirho.is_err());

        let bad_module_chirho = DagModuleChirho {
            name_chirho: "bad-schema-chirho".to_string(),
            dag_chirho: dag_hash_chirho,
            version_chirho: "v1".to_string(),
            previous_module_chirho: None,
            inputs_chirho: vec![DagModulePortChirho {
                public_port_chirho: PortChirho {
                    name_chirho: "request".to_string(),
                    schema_chirho: json_schema_chirho,
                },
                node_chirho: node_hash_chirho,
                node_port_chirho: "in".to_string(),
            }],
            outputs_chirho: vec![],
            route_labels_chirho: vec![],
            metadata_chirho: BTreeMap::new(),
        };
        assert!(validate_dag_module_chirho(&root_chirho, &bad_module_chirho).is_err());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn dag_module_composition_expands_runs_and_groups_internals_chirho() {
        let root_chirho = tmp_root_chirho();
        let bytes_schema_chirho = crate::cas_chirho::add_chirho(&root_chirho, b"bytes").unwrap();
        let upcase_node_chirho = runnable_node_chirho(
            &root_chirho,
            "upcase_chirho",
            include_str!("../../examples-chirho/upcase-chirho.wat"),
            "upcase_chirho",
            bytes_schema_chirho.clone(),
        );
        let reverse_node_chirho = runnable_node_chirho(
            &root_chirho,
            "reverse_chirho",
            include_str!("../../examples-chirho/reverse-chirho.wat"),
            "reverse_chirho",
            bytes_schema_chirho,
        );
        let (_upcase_module_chirho, upcase_module_hash_chirho, upcase_dag_hash_chirho) =
            single_node_module_chirho(&root_chirho, "upcase-module-chirho", upcase_node_chirho);
        let (_reverse_module_chirho, reverse_module_hash_chirho, _reverse_dag_hash_chirho) =
            single_node_module_chirho(&root_chirho, "reverse-module-chirho", reverse_node_chirho);

        let (composition_chirho, composition_hash_chirho) = build_dag_module_composition_chirho(
            &root_chirho,
            DagModuleCompositionBuildInputChirho {
                name_chirho: "upcase-reverse-chirho".to_string(),
                version_chirho: "v1".to_string(),
                instances_chirho: vec![
                    DagModuleInstanceInputChirho {
                        instance_chirho: "upcase".to_string(),
                        module_chirho: upcase_module_hash_chirho.clone(),
                    },
                    DagModuleInstanceInputChirho {
                        instance_chirho: "reverse".to_string(),
                        module_chirho: reverse_module_hash_chirho.clone(),
                    },
                ],
                wires_chirho: vec![DagModuleWireInputChirho {
                    from_instance_chirho: "upcase".to_string(),
                    from_port_chirho: "response".to_string(),
                    to_instance_chirho: "reverse".to_string(),
                    to_port_chirho: "request".to_string(),
                }],
                input_bindings_chirho: vec![DagModuleCompositionBindingInputChirho {
                    public_name_chirho: "request".to_string(),
                    instance_chirho: "upcase".to_string(),
                    module_port_chirho: "request".to_string(),
                }],
                output_bindings_chirho: vec![DagModuleCompositionBindingInputChirho {
                    public_name_chirho: "response".to_string(),
                    instance_chirho: "reverse".to_string(),
                    module_port_chirho: "response".to_string(),
                }],
                metadata_chirho: BTreeMap::new(),
            },
        )
        .unwrap();

        assert_ne!(
            composition_chirho.composed_dag_chirho,
            upcase_dag_hash_chirho
        );
        assert_eq!(composition_chirho.wires_chirho.len(), 1);
        validate_stored_dag_module_composition_chirho(&root_chirho, &composition_hash_chirho)
            .unwrap();

        let run_chirho =
            run_dag_module_composition_chirho(&root_chirho, &composition_hash_chirho, b"abc")
                .unwrap();
        assert_eq!(run_chirho.dag_report_chirho.payload_chirho, b"CBA");
        assert_eq!(run_chirho.dag_report_chirho.node_runs_chirho.len(), 2);
        assert_eq!(run_chirho.instance_runs_chirho.len(), 2);
        assert!(run_chirho
            .instance_runs_chirho
            .iter()
            .all(|instance_chirho| instance_chirho.node_runs_chirho.len() == 1));
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn dag_module_composition_rejects_schema_mismatch_before_run_chirho() {
        let root_chirho = tmp_root_chirho();
        let bytes_schema_chirho = crate::cas_chirho::add_chirho(&root_chirho, b"bytes").unwrap();
        let json_schema_chirho = crate::cas_chirho::add_chirho(&root_chirho, b"json").unwrap();
        let source_node_chirho = node_chirho(
            &root_chirho,
            "source_chirho",
            bytes_schema_chirho.clone(),
            bytes_schema_chirho,
        );
        let sink_node_chirho = node_chirho(
            &root_chirho,
            "sink_chirho",
            json_schema_chirho.clone(),
            json_schema_chirho,
        );
        let (_source_module_chirho, source_module_hash_chirho, _source_dag_hash_chirho) =
            single_node_module_chirho(&root_chirho, "source-module-chirho", source_node_chirho);
        let (_sink_module_chirho, sink_module_hash_chirho, _sink_dag_hash_chirho) =
            single_node_module_chirho(&root_chirho, "sink-module-chirho", sink_node_chirho);

        let bad_chirho = build_dag_module_composition_chirho(
            &root_chirho,
            DagModuleCompositionBuildInputChirho {
                name_chirho: "bad-composition-chirho".to_string(),
                version_chirho: "v1".to_string(),
                instances_chirho: vec![
                    DagModuleInstanceInputChirho {
                        instance_chirho: "source".to_string(),
                        module_chirho: source_module_hash_chirho,
                    },
                    DagModuleInstanceInputChirho {
                        instance_chirho: "sink".to_string(),
                        module_chirho: sink_module_hash_chirho,
                    },
                ],
                wires_chirho: vec![DagModuleWireInputChirho {
                    from_instance_chirho: "source".to_string(),
                    from_port_chirho: "response".to_string(),
                    to_instance_chirho: "sink".to_string(),
                    to_port_chirho: "request".to_string(),
                }],
                input_bindings_chirho: vec![DagModuleCompositionBindingInputChirho {
                    public_name_chirho: "request".to_string(),
                    instance_chirho: "source".to_string(),
                    module_port_chirho: "request".to_string(),
                }],
                output_bindings_chirho: vec![DagModuleCompositionBindingInputChirho {
                    public_name_chirho: "response".to_string(),
                    instance_chirho: "sink".to_string(),
                    module_port_chirho: "response".to_string(),
                }],
                metadata_chirho: BTreeMap::new(),
            },
        );
        assert!(bad_chirho.is_err());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
