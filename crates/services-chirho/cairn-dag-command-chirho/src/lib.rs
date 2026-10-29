// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! DAG, node-build, blessed-effect registry, placement, and metadata command bodies.

use cairn_chirho::model_chirho::{
    CapabilityChirho, DagChirho, EdgeChirho, HashChirho, NodeDefChirho, PortChirho,
};
use cairn_chirho::{
    app_chirho, blessed_chirho, cas_chirho, compile_chirho, dag_author_chirho, dag_chirho,
    dag_module_chirho, graph_chirho, identity_chirho, native_worker_chirho, placement_chirho,
    runner_chirho, store_chirho,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Path of the versioned MVCC store within a cairn root.
pub fn kv_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("versioned-chirho.redb")
}

pub fn ensure_demo_owner_chirho(
    root_chirho: &Path,
    app_name_chirho: &str,
) -> anyhow::Result<String> {
    if let Some(owner_chirho) = app_chirho::verified_app_owner_chirho(root_chirho, app_name_chirho)?
    {
        return Ok(owner_chirho);
    }
    Ok(identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )?
    .principal_chirho)
}

pub fn write_node_template_chirho(out_chirho: &Path) -> anyhow::Result<()> {
    const NODE_TEMPLATE_CHIRHO: &str =
        include_str!("../../../../examples-chirho/node-template-chirho.wat");
    std::fs::write(out_chirho, NODE_TEMPLATE_CHIRHO)?;
    println!(
        "wrote a pure bytes-ABI node template to {} (edit it, then: node-build <file> --name <n> --entry node_chirho)",
        out_chirho.display()
    );
    Ok(())
}

pub fn print_blessed_registry_chirho(root_chirho: &Path) -> anyhow::Result<()> {
    let registry_chirho = blessed_chirho::signed_registry_chirho(root_chirho)?;
    println!(
        "blessed-effect registry ({} kinds), signed by instance pubkey {}:",
        registry_chirho.effects_chirho.len(),
        registry_chirho.pubkey_chirho
    );
    for spec_chirho in &registry_chirho.effects_chirho {
        println!(
            "  - {}\tcompensation={}",
            spec_chirho.kind_chirho,
            blessed_chirho::compensation_kind_label_chirho(&spec_chirho.compensation_kind_chirho)
        );
    }
    println!(
        "signature: {}",
        if blessed_chirho::verify_registry_chirho(&registry_chirho) {
            "VALID"
        } else {
            "INVALID"
        }
    );
    println!("app code cannot extend this set — effects resolve only through these signed kinds.");
    Ok(())
}

pub fn cas_add_file_chirho(root_chirho: &Path, file_chirho: &Path) -> anyhow::Result<()> {
    let bytes_chirho = std::fs::read(file_chirho)?;
    let addr_chirho = cas_chirho::add_chirho(root_chirho, &bytes_chirho)?;
    println!("{}", addr_chirho.0);
    Ok(())
}

pub fn run_example_node_chirho(root_chirho: &Path, input_chirho: i64) -> anyhow::Result<()> {
    const DOUBLE_WAT_CHIRHO: &str = include_str!("../../../../examples-chirho/double-chirho.wat");
    let wasm_chirho = DOUBLE_WAT_CHIRHO.as_bytes();
    let (node_def_chirho, node_hash_chirho) = build_example_node_chirho(root_chirho, wasm_chirho)?;
    let (result_chirho, hit_chirho) = cairn_chirho::cache_chirho::run_node_cached_chirho(
        root_chirho,
        &node_def_chirho,
        &node_hash_chirho,
        wasm_chirho,
        input_chirho,
    )?;
    let out_hash_chirho = result_chirho
        .outputs_chirho
        .get("out")
        .expect("output port 'out'");
    let output_chirho: i64 = store_chirho::get_object_chirho(root_chirho, out_hash_chirho)?;
    let fuel_chirho = result_chirho.fuel_used_chirho;
    let tag_chirho = if hit_chirho { "  [cached]" } else { "" };
    println!(
        "double_chirho({input_chirho}) = {output_chirho}   [fuel used: {fuel_chirho}]{tag_chirho}"
    );
    println!("run {}", result_chirho.run_chirho.0);
    Ok(())
}

pub fn node_build_command_chirho(
    root_chirho: &Path,
    wasm_chirho: &Path,
    name_chirho: Option<&str>,
    entry_chirho: Option<&str>,
    fuel_chirho: u64,
) -> anyhow::Result<()> {
    let bytes_chirho = std::fs::read(wasm_chirho)?;
    let stem_chirho = wasm_chirho
        .file_stem()
        .and_then(|s_chirho| s_chirho.to_str())
        .unwrap_or("node")
        .to_string();
    let name_val_chirho = name_chirho
        .map(str::to_string)
        .unwrap_or_else(|| stem_chirho);
    let entry_val_chirho = entry_chirho
        .map(str::to_string)
        .unwrap_or_else(|| name_val_chirho.clone());
    let (_node_chirho, node_hash_chirho) = build_node_def_chirho(
        root_chirho,
        &name_val_chirho,
        &bytes_chirho,
        &entry_val_chirho,
        fuel_chirho,
    )?;
    println!("{}", node_hash_chirho.0);
    Ok(())
}

pub fn node_check_command_chirho(
    root_chirho: &Path,
    node_chirho: &str,
    input_chirho: Option<&str>,
) -> anyhow::Result<()> {
    let def_chirho: NodeDefChirho =
        store_chirho::get_object_chirho(root_chirho, &HashChirho(node_chirho.to_string()))?;
    let native_spec_chirho =
        native_worker_chirho::native_node_spec_from_impl_chirho(&def_chirho.impl_wasm_chirho);
    let mut problems_chirho: Vec<String> = Vec::new();
    if def_chirho.entry_chirho.is_empty() {
        problems_chirho.push("empty entry".to_string());
    }
    if def_chirho.fuel_limit_chirho == 0 && native_spec_chirho.is_none() {
        problems_chirho.push("fuel_limit is 0".to_string());
    }
    if def_chirho.inputs_chirho.is_empty() {
        problems_chirho.push("no input ports".to_string());
    }
    if def_chirho.outputs_chirho.is_empty() {
        problems_chirho.push("no output ports".to_string());
    }
    println!(
        "node '{}': entry={} fuel={} pure={} caps={} in={} out={}",
        def_chirho.name_chirho,
        def_chirho.entry_chirho,
        def_chirho.fuel_limit_chirho,
        def_chirho.is_pure_chirho(),
        def_chirho.capabilities_chirho.len(),
        def_chirho.inputs_chirho.len(),
        def_chirho.outputs_chirho.len()
    );
    if problems_chirho.is_empty() {
        println!("  validation: OK");
    } else {
        println!("  validation PROBLEMS: {}", problems_chirho.join("; "));
    }
    if let Some(native_spec_chirho) = native_spec_chirho {
        native_worker_chirho::validate_native_node_def_chirho(
            root_chirho,
            &def_chirho,
            &native_spec_chirho,
        )?;
        println!("  native spec: {}", native_spec_chirho.0);
        if def_chirho.is_pure_chirho() {
            let sample_chirho = input_chirho.unwrap_or("hello");
            let input_hash_chirho = cas_chirho::add_chirho(root_chirho, sample_chirho.as_bytes())?;
            let (result_chirho, hit_chirho) =
                native_worker_chirho::run_native_program_node_cached_with_context_chirho(
                    root_chirho,
                    &native_spec_chirho,
                    &HashChirho(node_chirho.to_string()),
                    &input_hash_chirho,
                    &[],
                    None,
                )?;
            let output_hash_chirho = result_chirho.outputs_chirho.get("out").cloned();
            let output_chirho = output_hash_chirho
                .as_ref()
                .and_then(|hash_chirho| cas_chirho::get_chirho(root_chirho, hash_chirho).ok())
                .unwrap_or_default();
            let tag_chirho = if hit_chirho { "  [cached]" } else { "" };
            println!(
                "  ran native on {:?} -> {:?}{}",
                sample_chirho,
                String::from_utf8_lossy(&output_chirho),
                tag_chirho
            );
        } else {
            println!(
                "  native effectful node (caps != []): run via a DAG (dag-run) so request context and the effect layer are in play"
            );
        }
    } else if def_chirho.is_pure_chirho() {
        let wasm_chirho = cas_chirho::get_chirho(root_chirho, &def_chirho.impl_wasm_chirho)?;
        let sample_chirho = input_chirho.unwrap_or("hello");
        let outcome_chirho = runner_chirho::run_node_bytes_chirho(
            &wasm_chirho,
            &def_chirho.entry_chirho,
            sample_chirho.as_bytes(),
            def_chirho.fuel_limit_chirho,
        )?;
        println!(
            "  ran on {:?} -> {:?}  (fuel {})",
            sample_chirho,
            String::from_utf8_lossy(&outcome_chirho.output_chirho),
            outcome_chirho.fuel_used_chirho
        );
    } else {
        println!(
            "  effectful node (caps != []): run via a DAG (dag-run) so the effect layer is in play"
        );
    }
    Ok(())
}

pub struct DagModuleBuildCommandInputChirho<'a> {
    pub dag_chirho: &'a str,
    pub name_chirho: &'a str,
    pub version_chirho: &'a str,
    pub previous_chirho: Option<&'a str>,
    pub inputs_chirho: &'a [String],
    pub outputs_chirho: &'a [String],
    pub routes_chirho: &'a [String],
    pub metadata_chirho: &'a [String],
}

pub struct DagModuleComposeCommandInputChirho<'a> {
    pub name_chirho: &'a str,
    pub version_chirho: &'a str,
    pub instances_chirho: &'a [String],
    pub wires_chirho: &'a [String],
    pub inputs_chirho: &'a [String],
    pub outputs_chirho: &'a [String],
    pub metadata_chirho: &'a [String],
}

pub fn dag_graph_command_chirho(
    root_chirho: &Path,
    dag_chirho: &str,
    format_chirho: Option<&str>,
) -> anyhow::Result<()> {
    let dag_obj_chirho: DagChirho =
        store_chirho::get_object_chirho(root_chirho, &HashChirho(dag_chirho.to_string()))?;
    let graph_out_chirho = match format_chirho {
        Some("dot") => graph_chirho::dag_to_dot_chirho(root_chirho, &dag_obj_chirho)?,
        _ => graph_chirho::dag_to_mermaid_chirho(root_chirho, &dag_obj_chirho)?,
    };
    print!("{graph_out_chirho}");
    Ok(())
}

pub fn dag_module_build_command_chirho(
    root_chirho: &Path,
    input_chirho: DagModuleBuildCommandInputChirho<'_>,
) -> anyhow::Result<()> {
    let (_module_chirho, module_hash_chirho) = dag_module_chirho::build_dag_module_chirho(
        root_chirho,
        dag_module_chirho::DagModuleBuildInputChirho {
            name_chirho: input_chirho.name_chirho.to_string(),
            dag_chirho: HashChirho(input_chirho.dag_chirho.to_string()),
            version_chirho: input_chirho.version_chirho.to_string(),
            previous_module_chirho: input_chirho
                .previous_chirho
                .map(|value_chirho| HashChirho(value_chirho.to_string())),
            input_bindings_chirho: parse_dag_module_bindings_chirho(input_chirho.inputs_chirho)?,
            output_bindings_chirho: parse_dag_module_bindings_chirho(input_chirho.outputs_chirho)?,
            route_labels_chirho: input_chirho.routes_chirho.to_vec(),
            metadata_chirho: parse_metadata_chirho(input_chirho.metadata_chirho)?,
        },
    )?;
    println!("{}", module_hash_chirho.0);
    Ok(())
}

pub fn dag_module_show_command_chirho(
    root_chirho: &Path,
    module_chirho: &str,
) -> anyhow::Result<()> {
    let module_obj_chirho = dag_module_chirho::load_dag_module_chirho(
        root_chirho,
        &HashChirho(module_chirho.to_string()),
    )?;
    println!("{}", serde_json::to_string_pretty(&module_obj_chirho)?);
    Ok(())
}

pub fn dag_module_check_command_chirho(
    root_chirho: &Path,
    module_chirho: &str,
) -> anyhow::Result<()> {
    let module_obj_chirho = dag_module_chirho::validate_stored_dag_module_chirho(
        root_chirho,
        &HashChirho(module_chirho.to_string()),
    )?;
    println!(
        "module OK: {} dag={} inputs={} outputs={} routes={}",
        module_obj_chirho.name_chirho,
        module_obj_chirho.dag_chirho.0,
        module_obj_chirho.inputs_chirho.len(),
        module_obj_chirho.outputs_chirho.len(),
        module_obj_chirho.route_labels_chirho.len()
    );
    Ok(())
}

pub fn dag_module_compose_command_chirho(
    root_chirho: &Path,
    input_chirho: DagModuleComposeCommandInputChirho<'_>,
) -> anyhow::Result<()> {
    let (composition_obj_chirho, composition_hash_chirho) =
        dag_module_chirho::build_dag_module_composition_chirho(
            root_chirho,
            dag_module_chirho::DagModuleCompositionBuildInputChirho {
                name_chirho: input_chirho.name_chirho.to_string(),
                version_chirho: input_chirho.version_chirho.to_string(),
                instances_chirho: parse_dag_module_instances_chirho(input_chirho.instances_chirho)?,
                wires_chirho: parse_dag_module_wires_chirho(input_chirho.wires_chirho)?,
                input_bindings_chirho: parse_dag_module_composition_bindings_chirho(
                    input_chirho.inputs_chirho,
                )?,
                output_bindings_chirho: parse_dag_module_composition_bindings_chirho(
                    input_chirho.outputs_chirho,
                )?,
                metadata_chirho: parse_metadata_chirho(input_chirho.metadata_chirho)?,
            },
        )?;
    println!("composition {}", composition_hash_chirho.0);
    println!("dag {}", composition_obj_chirho.composed_dag_chirho.0);
    Ok(())
}

pub fn dag_module_composition_show_command_chirho(
    root_chirho: &Path,
    composition_chirho: &str,
) -> anyhow::Result<()> {
    let composition_obj_chirho = dag_module_chirho::load_dag_module_composition_chirho(
        root_chirho,
        &HashChirho(composition_chirho.to_string()),
    )?;
    println!("{}", serde_json::to_string_pretty(&composition_obj_chirho)?);
    Ok(())
}

pub fn dag_module_composition_check_command_chirho(
    root_chirho: &Path,
    composition_chirho: &str,
) -> anyhow::Result<()> {
    let composition_obj_chirho = dag_module_chirho::validate_stored_dag_module_composition_chirho(
        root_chirho,
        &HashChirho(composition_chirho.to_string()),
    )?;
    println!(
        "composition OK: {} dag={} instances={} wires={} inputs={} outputs={}",
        composition_obj_chirho.name_chirho,
        composition_obj_chirho.composed_dag_chirho.0,
        composition_obj_chirho.instances_chirho.len(),
        composition_obj_chirho.wires_chirho.len(),
        composition_obj_chirho.inputs_chirho.len(),
        composition_obj_chirho.outputs_chirho.len()
    );
    Ok(())
}

pub fn dag_module_run_command_chirho(
    root_chirho: &Path,
    composition_chirho: &str,
    input_chirho: &str,
) -> anyhow::Result<()> {
    let report_chirho = dag_module_chirho::run_dag_module_composition_chirho(
        root_chirho,
        &HashChirho(composition_chirho.to_string()),
        input_chirho.as_bytes(),
    )?;
    println!(
        "composition {} dag={}",
        report_chirho.composition_chirho.name_chirho,
        report_chirho.composition_chirho.composed_dag_chirho.0
    );
    for instance_chirho in &report_chirho.instance_runs_chirho {
        println!(
            "instance {} module={}",
            instance_chirho.instance_chirho, instance_chirho.module_chirho.0
        );
        for node_run_chirho in &instance_chirho.node_runs_chirho {
            let tag_chirho = if node_run_chirho.cached_chirho {
                " [cached]"
            } else {
                ""
            };
            println!(
                "  {:<16} run {}{}",
                node_run_chirho.node_name_chirho,
                &node_run_chirho.run_chirho.0[..16],
                tag_chirho
            );
        }
    }
    println!(
        "payload: {}",
        String::from_utf8_lossy(&report_chirho.dag_report_chirho.payload_chirho)
    );
    Ok(())
}

pub fn dag_run_command_chirho(
    root_chirho: &Path,
    dag_chirho: &str,
    input_chirho: &str,
) -> anyhow::Result<()> {
    let dag_obj_chirho: DagChirho =
        store_chirho::get_object_chirho(root_chirho, &HashChirho(dag_chirho.to_string()))?;
    let report_chirho = dag_chirho::run_dag_as_operator_chirho(
        root_chirho,
        &dag_obj_chirho,
        input_chirho.as_bytes(),
    )?;
    print_dag_report_chirho(&report_chirho);
    Ok(())
}

pub fn dag_build_command_chirho(
    root_chirho: &Path,
    nodes_chirho: &[String],
    edges_chirho: &[String],
) -> anyhow::Result<()> {
    let (_dag_chirho, dag_hash_chirho) = dag_author_chirho::build_dag_chirho(
        root_chirho,
        dag_author_chirho::DagBuildInputChirho {
            nodes_chirho: nodes_chirho.iter().cloned().map(HashChirho).collect(),
            edges_chirho: edges_chirho
                .iter()
                .map(|edge_chirho| dag_author_chirho::parse_dag_edge_spec_chirho(edge_chirho))
                .collect::<anyhow::Result<Vec<_>>>()?,
        },
    )?;
    println!("{}", dag_hash_chirho.0);
    Ok(())
}

pub fn dag_demo_command_chirho(root_chirho: &Path, input_chirho: &str) -> anyhow::Result<()> {
    const UPCASE_WAT_CHIRHO: &str = include_str!("../../../../examples-chirho/upcase-chirho.wat");
    const REVERSE_WAT_CHIRHO: &str = include_str!("../../../../examples-chirho/reverse-chirho.wat");
    let (_upcase_def_chirho, upcase_hash_chirho) = build_bytes_node_chirho(
        root_chirho,
        "upcase_chirho",
        UPCASE_WAT_CHIRHO.as_bytes(),
        "upcase_chirho",
    )?;
    let (_reverse_def_chirho, reverse_hash_chirho) = build_bytes_node_chirho(
        root_chirho,
        "reverse_chirho",
        REVERSE_WAT_CHIRHO.as_bytes(),
        "reverse_chirho",
    )?;
    let dag_obj_chirho = DagChirho {
        nodes_chirho: vec![upcase_hash_chirho.clone(), reverse_hash_chirho.clone()],
        edges_chirho: vec![EdgeChirho {
            from_node_chirho: upcase_hash_chirho,
            from_port_chirho: "out".to_string(),
            to_node_chirho: reverse_hash_chirho,
            to_port_chirho: "in".to_string(),
            privacy_chirho: None,
        }],
    };
    let dag_hash_chirho = store_chirho::put_object_chirho(root_chirho, &dag_obj_chirho)?;
    println!("dag {}", dag_hash_chirho.0);
    let report_chirho = dag_chirho::run_dag_as_operator_chirho(
        root_chirho,
        &dag_obj_chirho,
        input_chirho.as_bytes(),
    )?;
    print_dag_report_chirho(&report_chirho);
    Ok(())
}

pub fn dag_effect_demo_command_chirho(root_chirho: &Path, key_chirho: &str) -> anyhow::Result<()> {
    const UPCASE_WAT_CHIRHO: &str = include_str!("../../../../examples-chirho/upcase-chirho.wat");
    let (_read_def_chirho, read_hash_chirho) = build_effect_node_chirho(
        root_chirho,
        "read_chirho",
        CapabilityChirho::ReadStoreChirho {
            prefix_chirho: key_chirho.to_string(),
        },
    )?;
    let (_upcase_def_chirho, upcase_hash_chirho) = build_bytes_node_chirho(
        root_chirho,
        "upcase_chirho",
        UPCASE_WAT_CHIRHO.as_bytes(),
        "upcase_chirho",
    )?;
    let dag_obj_chirho = DagChirho {
        nodes_chirho: vec![read_hash_chirho.clone(), upcase_hash_chirho.clone()],
        edges_chirho: vec![EdgeChirho {
            from_node_chirho: read_hash_chirho,
            from_port_chirho: "out".to_string(),
            to_node_chirho: upcase_hash_chirho,
            to_port_chirho: "in".to_string(),
            privacy_chirho: None,
        }],
    };
    let dag_hash_chirho = store_chirho::put_object_chirho(root_chirho, &dag_obj_chirho)?;
    println!("dag {}", dag_hash_chirho.0);
    let report_chirho = dag_chirho::run_dag_as_operator_chirho(root_chirho, &dag_obj_chirho, b"")?;
    print_dag_report_chirho(&report_chirho);
    Ok(())
}

pub fn compile_demo_command_chirho(root_chirho: &Path, out_chirho: &Path) -> anyhow::Result<()> {
    const UPCASE_WAT_CHIRHO: &str = include_str!("../../../../examples-chirho/upcase-chirho.wat");
    let (_def_chirho, node_hash_chirho) = build_bytes_node_chirho(
        root_chirho,
        "upcase_chirho",
        UPCASE_WAT_CHIRHO.as_bytes(),
        "upcase_chirho",
    )?;
    let dag_obj_chirho = DagChirho {
        nodes_chirho: vec![node_hash_chirho],
        edges_chirho: vec![],
    };
    let artifact_hash_chirho = compile_chirho::compile_dag_chirho(root_chirho, &dag_obj_chirho)?;
    let artifact_chirho = cas_chirho::get_chirho(root_chirho, &artifact_hash_chirho)?;
    std::fs::write(out_chirho, &artifact_chirho)?;
    println!(
        "compiled upcase DAG -> {} ({} bytes) -> {}",
        artifact_hash_chirho.0,
        artifact_chirho.len(),
        out_chirho.display()
    );
    Ok(())
}

pub fn compile_chain_demo_command_chirho(out_chirho: &Path) -> anyhow::Result<()> {
    const UPCASE_STEP_CHIRHO: &str =
        include_str!("../../../../examples-chirho/upcase-step-chirho.wat");
    const REVERSE_STEP_CHIRHO: &str =
        include_str!("../../../../examples-chirho/reverse-step-chirho.wat");
    let wasm_chirho =
        compile_chirho::compose_steps_chirho(&[UPCASE_STEP_CHIRHO, REVERSE_STEP_CHIRHO])?;
    std::fs::write(out_chirho, &wasm_chirho)?;
    println!(
        "composed upcase->reverse chain -> {} bytes -> {}",
        wasm_chirho.len(),
        out_chirho.display()
    );
    Ok(())
}

pub fn compile_effect_demo_command_chirho(out_chirho: &Path) -> anyhow::Result<()> {
    let wasm_chirho = compile_chirho::demo_effect_chain_wasm_chirho()?;
    std::fs::write(out_chirho, &wasm_chirho)?;
    println!(
        "composed effectful upcase->dom_patch -> {} bytes -> {} (imports cairn_chirho.dom_patch_chirho)",
        wasm_chirho.len(),
        out_chirho.display()
    );
    Ok(())
}

/// Print a DAG run report: each node's run id + cache status, then the payload.
fn print_dag_report_chirho(report_chirho: &dag_chirho::DagRunReportChirho) {
    for node_run_chirho in &report_chirho.node_runs_chirho {
        let tag_chirho = if node_run_chirho.cached_chirho {
            "  [cached]"
        } else {
            ""
        };
        println!(
            "  {:<16} run {}{}",
            node_run_chirho.node_name_chirho,
            &node_run_chirho.run_chirho.0[..16],
            tag_chirho
        );
    }
    println!(
        "payload: {}",
        String::from_utf8_lossy(&report_chirho.payload_chirho)
    );
}

/// Assemble the bundled example as a real, content-addressed NodeDefChirho (pure, scalar).
pub fn build_example_node_chirho(
    root_chirho: &Path,
    wasm_chirho: &[u8],
) -> anyhow::Result<(NodeDefChirho, HashChirho)> {
    build_node_def_chirho(
        root_chirho,
        "double_chirho",
        wasm_chirho,
        "double_chirho",
        1_000_000,
    )
}

/// Assemble a pure bytes node (its WASM + a placeholder schema + the node def), fuel-capped.
pub fn build_node_def_chirho(
    root_chirho: &Path,
    name_chirho: &str,
    wasm_chirho: &[u8],
    entry_chirho: &str,
    fuel_chirho: u64,
) -> anyhow::Result<(NodeDefChirho, HashChirho)> {
    let impl_hash_chirho = cas_chirho::add_chirho(root_chirho, wasm_chirho)?;
    let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes")?;
    let node_chirho = NodeDefChirho {
        name_chirho: name_chirho.to_string(),
        impl_wasm_chirho: impl_hash_chirho,
        entry_chirho: entry_chirho.to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho: vec![],
        effect_contract_set_chirho: None,
        fuel_limit_chirho: fuel_chirho,
        max_output_bytes_chirho: cairn_chirho::model_chirho::DEFAULT_NODE_MAX_OUTPUT_BYTES_CHIRHO,
        max_memory_bytes_chirho: cairn_chirho::model_chirho::DEFAULT_NODE_MAX_MEMORY_BYTES_CHIRHO,
    };
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho)?;
    Ok((node_chirho, node_hash_chirho))
}

/// A pure bytes node with the default fuel cap (used by the demo commands).
pub fn build_bytes_node_chirho(
    root_chirho: &Path,
    name_chirho: &str,
    wasm_chirho: &[u8],
    entry_chirho: &str,
) -> anyhow::Result<(NodeDefChirho, HashChirho)> {
    build_node_def_chirho(
        root_chirho,
        name_chirho,
        wasm_chirho,
        entry_chirho,
        1_000_000,
    )
}

/// Assemble a built-in effect node (a `NodeDefChirho` carrying one capability).
pub fn build_effect_node_chirho(
    root_chirho: &Path,
    name_chirho: &str,
    capability_chirho: CapabilityChirho,
) -> anyhow::Result<(NodeDefChirho, HashChirho)> {
    let impl_hash_chirho =
        cas_chirho::add_chirho(root_chirho, format!("builtin:{name_chirho}").as_bytes())?;
    let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes")?;
    let node_chirho = NodeDefChirho {
        name_chirho: name_chirho.to_string(),
        impl_wasm_chirho: impl_hash_chirho,
        entry_chirho: name_chirho.to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho: vec![capability_chirho],
        effect_contract_set_chirho: None,
        fuel_limit_chirho: 0,
        max_output_bytes_chirho: cairn_chirho::model_chirho::DEFAULT_NODE_MAX_OUTPUT_BYTES_CHIRHO,
        max_memory_bytes_chirho: cairn_chirho::model_chirho::DEFAULT_NODE_MAX_MEMORY_BYTES_CHIRHO,
    };
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho)?;
    Ok((node_chirho, node_hash_chirho))
}

pub fn parse_dag_module_bindings_chirho(
    specs_chirho: &[String],
) -> anyhow::Result<Vec<dag_module_chirho::DagModuleBindingInputChirho>> {
    specs_chirho
        .iter()
        .map(|spec_chirho| parse_dag_module_binding_chirho(spec_chirho))
        .collect()
}

fn parse_dag_module_binding_chirho(
    spec_chirho: &str,
) -> anyhow::Result<dag_module_chirho::DagModuleBindingInputChirho> {
    let (public_chirho, target_chirho) = spec_chirho.split_once('=').ok_or_else(|| {
        anyhow::anyhow!("module binding '{spec_chirho}' must be public=node_hash:node_port")
    })?;
    let (node_chirho, node_port_chirho) = target_chirho.split_once(':').ok_or_else(|| {
        anyhow::anyhow!("module binding '{spec_chirho}' must be public=node_hash:node_port")
    })?;
    if public_chirho.trim().is_empty()
        || node_chirho.trim().is_empty()
        || node_port_chirho.trim().is_empty()
        || node_port_chirho.contains(':')
    {
        anyhow::bail!("module binding '{spec_chirho}' must be public=node_hash:node_port");
    }
    Ok(dag_module_chirho::DagModuleBindingInputChirho {
        public_name_chirho: public_chirho.to_string(),
        node_chirho: HashChirho(node_chirho.to_string()),
        node_port_chirho: node_port_chirho.to_string(),
    })
}

pub fn parse_dag_module_instances_chirho(
    specs_chirho: &[String],
) -> anyhow::Result<Vec<dag_module_chirho::DagModuleInstanceInputChirho>> {
    specs_chirho
        .iter()
        .map(|spec_chirho| {
            let (instance_chirho, module_chirho) =
                spec_chirho.split_once('=').ok_or_else(|| {
                    anyhow::anyhow!("module instance '{spec_chirho}' must be instance=module_hash")
                })?;
            if instance_chirho.trim().is_empty()
                || module_chirho.trim().is_empty()
                || module_chirho.contains('=')
            {
                anyhow::bail!("module instance '{spec_chirho}' must be instance=module_hash");
            }
            Ok(dag_module_chirho::DagModuleInstanceInputChirho {
                instance_chirho: instance_chirho.to_string(),
                module_chirho: HashChirho(module_chirho.to_string()),
            })
        })
        .collect()
}

pub fn parse_dag_module_wires_chirho(
    specs_chirho: &[String],
) -> anyhow::Result<Vec<dag_module_chirho::DagModuleWireInputChirho>> {
    specs_chirho
        .iter()
        .map(|spec_chirho| {
            let (from_chirho, to_chirho) = spec_chirho.split_once('=').ok_or_else(|| {
                anyhow::anyhow!(
                    "module wire '{spec_chirho}' must be from_instance:from_port=to_instance:to_port"
                )
            })?;
            let (from_instance_chirho, from_port_chirho) =
                parse_dag_module_instance_port_chirho(from_chirho, spec_chirho, "wire")?;
            let (to_instance_chirho, to_port_chirho) =
                parse_dag_module_instance_port_chirho(to_chirho, spec_chirho, "wire")?;
            Ok(dag_module_chirho::DagModuleWireInputChirho {
                from_instance_chirho,
                from_port_chirho,
                to_instance_chirho,
                to_port_chirho,
            })
        })
        .collect()
}

pub fn parse_dag_module_composition_bindings_chirho(
    specs_chirho: &[String],
) -> anyhow::Result<Vec<dag_module_chirho::DagModuleCompositionBindingInputChirho>> {
    specs_chirho
        .iter()
        .map(|spec_chirho| {
            let (public_chirho, target_chirho) = spec_chirho.split_once('=').ok_or_else(|| {
                anyhow::anyhow!(
                    "composition binding '{spec_chirho}' must be public=instance:module_port"
                )
            })?;
            let (instance_chirho, module_port_chirho) =
                parse_dag_module_instance_port_chirho(target_chirho, spec_chirho, "binding")?;
            if public_chirho.trim().is_empty() {
                anyhow::bail!(
                    "composition binding '{spec_chirho}' must be public=instance:module_port"
                );
            }
            Ok(dag_module_chirho::DagModuleCompositionBindingInputChirho {
                public_name_chirho: public_chirho.to_string(),
                instance_chirho,
                module_port_chirho,
            })
        })
        .collect()
}

fn parse_dag_module_instance_port_chirho(
    target_chirho: &str,
    spec_chirho: &str,
    kind_chirho: &str,
) -> anyhow::Result<(String, String)> {
    let (instance_chirho, port_chirho) = target_chirho.split_once(':').ok_or_else(|| {
        anyhow::anyhow!("module {kind_chirho} '{spec_chirho}' must use instance:port endpoints")
    })?;
    if instance_chirho.trim().is_empty()
        || port_chirho.trim().is_empty()
        || port_chirho.contains(':')
    {
        anyhow::bail!("module {kind_chirho} '{spec_chirho}' must use instance:port endpoints");
    }
    Ok((instance_chirho.to_string(), port_chirho.to_string()))
}

pub fn parse_placement_constraints_chirho(
    hardware_chirho: &[String],
    regions_chirho: &[String],
    data_regions_chirho: &[String],
    features_chirho: &[String],
) -> Vec<placement_chirho::PlacementHardConstraintChirho> {
    let mut out_chirho = Vec::new();
    out_chirho.extend(hardware_chirho.iter().cloned().map(|hardware_chirho| {
        placement_chirho::PlacementHardConstraintChirho::RequiredHardwareChirho { hardware_chirho }
    }));
    out_chirho.extend(regions_chirho.iter().cloned().map(|region_chirho| {
        placement_chirho::PlacementHardConstraintChirho::RequiredRegionChirho { region_chirho }
    }));
    out_chirho.extend(data_regions_chirho.iter().cloned().map(|region_chirho| {
        placement_chirho::PlacementHardConstraintChirho::DataResidencyRegionChirho { region_chirho }
    }));
    out_chirho.extend(features_chirho.iter().cloned().map(|feature_chirho| {
        placement_chirho::PlacementHardConstraintChirho::RequiredFeatureChirho { feature_chirho }
    }));
    out_chirho
}

pub fn parse_placement_affinities_chirho(
    specs_chirho: &[String],
) -> anyhow::Result<Vec<placement_chirho::PlacementAffinityChirho>> {
    specs_chirho
        .iter()
        .map(|spec_chirho| {
            let (left_chirho, weight_chirho) = spec_chirho.rsplit_once(':').ok_or_else(|| {
                anyhow::anyhow!("placement affinity '{spec_chirho}' must be kind=value:weight")
            })?;
            let weight_chirho: i64 = weight_chirho
                .parse()
                .map_err(|e_chirho| anyhow::anyhow!("bad affinity weight: {e_chirho}"))?;
            let (kind_chirho, value_chirho) = left_chirho.split_once('=').ok_or_else(|| {
                anyhow::anyhow!("placement affinity '{spec_chirho}' must be kind=value:weight")
            })?;
            if value_chirho.trim().is_empty() {
                anyhow::bail!("placement affinity '{spec_chirho}' must be kind=value:weight");
            }
            let kind_chirho = match kind_chirho {
                "previous-warm-location" => {
                    placement_chirho::PlacementAffinityKindChirho::PreviousWarmLocationChirho {
                        location_chirho: value_chirho.to_string(),
                    }
                }
                "colocate-module" => {
                    placement_chirho::PlacementAffinityKindChirho::ColocateWithModuleChirho {
                        module_chirho: HashChirho(value_chirho.to_string()),
                    }
                }
                "user-cache" => {
                    placement_chirho::PlacementAffinityKindChirho::ColocateWithUserCacheChirho {
                        user_chirho: value_chirho.to_string(),
                    }
                }
                "model" => placement_chirho::PlacementAffinityKindChirho::ColocateWithModelChirho {
                    model_chirho: value_chirho.to_string(),
                },
                "data-region" => {
                    placement_chirho::PlacementAffinityKindChirho::DataLocalityChirho {
                        region_chirho: value_chirho.to_string(),
                    }
                }
                "accelerator" => {
                    placement_chirho::PlacementAffinityKindChirho::PreferredAcceleratorChirho {
                        accelerator_chirho: value_chirho.to_string(),
                    }
                }
                "egress-price-ceiling" => {
                    let max_micros_per_gib_chirho =
                        value_chirho.parse::<u64>().map_err(|e_chirho| {
                            anyhow::anyhow!("bad egress price ceiling '{value_chirho}': {e_chirho}")
                        })?;
                    placement_chirho::PlacementAffinityKindChirho::EgressPriceCeilingChirho {
                        max_micros_per_gib_chirho,
                    }
                }
                other_chirho => {
                    anyhow::bail!("unknown placement affinity kind '{other_chirho}'")
                }
            };
            Ok(placement_chirho::PlacementAffinityChirho {
                kind_chirho,
                weight_chirho,
            })
        })
        .collect()
}

pub fn parse_placement_candidate_chirho(
    spec_chirho: &str,
) -> anyhow::Result<placement_chirho::PlacementCandidateChirho> {
    let mut candidate_chirho = None;
    let mut region_chirho = None;
    let mut hardware_chirho = Vec::new();
    let mut features_chirho = Vec::new();
    let mut resident_modules_chirho = Vec::new();
    let mut user_caches_chirho = Vec::new();
    let mut resident_models_chirho = Vec::new();
    let mut data_regions_chirho = Vec::new();
    let mut accelerators_chirho = Vec::new();
    let mut egress_price_micros_per_gib_chirho = None;
    for part_chirho in spec_chirho.split(',') {
        let (key_chirho, value_chirho) = part_chirho.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("placement candidate '{spec_chirho}' must be comma-separated key=value")
        })?;
        if value_chirho.trim().is_empty() {
            anyhow::bail!("placement candidate '{spec_chirho}' has an empty value");
        }
        match key_chirho {
            "id" => candidate_chirho = Some(value_chirho.to_string()),
            "region" => region_chirho = Some(value_chirho.to_string()),
            "hardware" => hardware_chirho.push(value_chirho.to_string()),
            "feature" => features_chirho.push(value_chirho.to_string()),
            "module" | "resident-module" => {
                resident_modules_chirho.push(HashChirho(value_chirho.to_string()))
            }
            "user-cache" => user_caches_chirho.push(value_chirho.to_string()),
            "model" => resident_models_chirho.push(value_chirho.to_string()),
            "data-region" => data_regions_chirho.push(value_chirho.to_string()),
            "accelerator" => accelerators_chirho.push(value_chirho.to_string()),
            "egress-price-micros-per-gib" => {
                egress_price_micros_per_gib_chirho =
                    Some(value_chirho.parse::<u64>().map_err(|e_chirho| {
                        anyhow::anyhow!("bad egress price '{value_chirho}': {e_chirho}")
                    })?)
            }
            other_chirho => anyhow::bail!("unknown placement candidate key '{other_chirho}'"),
        }
    }
    Ok(placement_chirho::PlacementCandidateChirho {
        candidate_chirho: candidate_chirho.ok_or_else(|| {
            anyhow::anyhow!("placement candidate '{spec_chirho}' needs id=<candidate>")
        })?,
        region_chirho: region_chirho.ok_or_else(|| {
            anyhow::anyhow!("placement candidate '{spec_chirho}' needs region=<region>")
        })?,
        hardware_chirho,
        features_chirho,
        resident_modules_chirho,
        user_caches_chirho,
        resident_models_chirho,
        data_regions_chirho,
        accelerators_chirho,
        egress_price_micros_per_gib_chirho,
    })
}

pub fn parse_metadata_chirho(specs_chirho: &[String]) -> anyhow::Result<BTreeMap<String, String>> {
    let mut metadata_chirho = BTreeMap::new();
    for spec_chirho in specs_chirho {
        let (key_chirho, value_chirho) = spec_chirho
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("metadata '{spec_chirho}' must be key=value"))?;
        if key_chirho.trim().is_empty() {
            anyhow::bail!("metadata key must not be empty");
        }
        if metadata_chirho
            .insert(key_chirho.to_string(), value_chirho.to_string())
            .is_some()
        {
            anyhow::bail!("duplicate metadata key '{key_chirho}'");
        }
    }
    Ok(metadata_chirho)
}
