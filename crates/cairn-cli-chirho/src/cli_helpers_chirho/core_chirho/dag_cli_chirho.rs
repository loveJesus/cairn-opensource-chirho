// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Thin CLI shell for DAG, node-build, blessed-effect, and placement-candidate parsing.

use crate::args_chirho::CommandChirho;
use cairn_dag_command_chirho as dag_command_chirho;
use std::path::Path;

pub(crate) use dag_command_chirho::parse_placement_candidate_chirho;

pub(crate) fn handle_dag_utility_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::NodeTemplateChirho { out_chirho } => {
            dag_command_chirho::write_node_template_chirho(out_chirho)?;
            Ok(true)
        }
        CommandChirho::BlessedChirho => {
            dag_command_chirho::print_blessed_registry_chirho(root_chirho)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

pub(crate) fn handle_cas_node_build_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::CasAddChirho { file_chirho } => {
            dag_command_chirho::cas_add_file_chirho(root_chirho, file_chirho)?;
            Ok(true)
        }
        CommandChirho::RunNodeChirho(args_chirho) => {
            dag_command_chirho::run_example_node_chirho(root_chirho, args_chirho.input_chirho)?;
            Ok(true)
        }
        CommandChirho::NodeBuildChirho(args_chirho) => {
            dag_command_chirho::node_build_command_chirho(
                root_chirho,
                &args_chirho.wasm_chirho,
                args_chirho.name_chirho.as_deref(),
                args_chirho.entry_chirho.as_deref(),
                args_chirho.fuel_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::NodeCheckChirho(args_chirho) => {
            dag_command_chirho::node_check_command_chirho(
                root_chirho,
                &args_chirho.node_chirho,
                args_chirho.input_chirho.as_deref(),
            )?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

pub(crate) fn handle_dag_module_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::DagGraphChirho(args_chirho) => {
            dag_command_chirho::dag_graph_command_chirho(
                root_chirho,
                &args_chirho.dag_chirho,
                args_chirho.format_chirho.as_deref(),
            )?;
            Ok(true)
        }
        CommandChirho::DagModuleBuildChirho(args_chirho) => {
            dag_command_chirho::dag_module_build_command_chirho(
                root_chirho,
                dag_command_chirho::DagModuleBuildCommandInputChirho {
                    dag_chirho: &args_chirho.dag_chirho,
                    name_chirho: &args_chirho.name_chirho,
                    version_chirho: &args_chirho.version_chirho,
                    previous_chirho: args_chirho.previous_chirho.as_deref(),
                    inputs_chirho: &args_chirho.inputs_chirho,
                    outputs_chirho: &args_chirho.outputs_chirho,
                    routes_chirho: &args_chirho.routes_chirho,
                    metadata_chirho: &args_chirho.metadata_chirho,
                },
            )?;
            Ok(true)
        }
        CommandChirho::DagModuleShowChirho { module_chirho } => {
            dag_command_chirho::dag_module_show_command_chirho(root_chirho, module_chirho)?;
            Ok(true)
        }
        CommandChirho::DagModuleCheckChirho { module_chirho } => {
            dag_command_chirho::dag_module_check_command_chirho(root_chirho, module_chirho)?;
            Ok(true)
        }
        CommandChirho::DagModuleComposeChirho(args_chirho) => {
            dag_command_chirho::dag_module_compose_command_chirho(
                root_chirho,
                dag_command_chirho::DagModuleComposeCommandInputChirho {
                    name_chirho: &args_chirho.name_chirho,
                    version_chirho: &args_chirho.version_chirho,
                    instances_chirho: &args_chirho.instances_chirho,
                    wires_chirho: &args_chirho.wires_chirho,
                    inputs_chirho: &args_chirho.inputs_chirho,
                    outputs_chirho: &args_chirho.outputs_chirho,
                    metadata_chirho: &args_chirho.metadata_chirho,
                },
            )?;
            Ok(true)
        }
        CommandChirho::DagModuleCompositionShowChirho { composition_chirho } => {
            dag_command_chirho::dag_module_composition_show_command_chirho(
                root_chirho,
                composition_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::DagModuleCompositionCheckChirho { composition_chirho } => {
            dag_command_chirho::dag_module_composition_check_command_chirho(
                root_chirho,
                composition_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::DagModuleRunChirho(args_chirho) => {
            dag_command_chirho::dag_module_run_command_chirho(
                root_chirho,
                &args_chirho.composition_chirho,
                &args_chirho.input_chirho,
            )?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

pub(crate) fn handle_core_dag_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::DagRunChirho(args_chirho) => {
            dag_command_chirho::dag_run_command_chirho(
                root_chirho,
                &args_chirho.dag_chirho,
                &args_chirho.input_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::DagBuildChirho(args_chirho) => {
            dag_command_chirho::dag_build_command_chirho(
                root_chirho,
                &args_chirho.nodes_chirho,
                &args_chirho.edges_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::DagDemoChirho { input_chirho } => {
            dag_command_chirho::dag_demo_command_chirho(root_chirho, input_chirho)?;
            Ok(true)
        }
        CommandChirho::DagEffectDemoChirho { key_chirho } => {
            dag_command_chirho::dag_effect_demo_command_chirho(root_chirho, key_chirho)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

pub(crate) fn handle_compile_demo_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::CompileDemoChirho { out_chirho } => {
            dag_command_chirho::compile_demo_command_chirho(root_chirho, out_chirho)?;
            Ok(true)
        }
        CommandChirho::CompileChainDemoChirho { out_chirho } => {
            dag_command_chirho::compile_chain_demo_command_chirho(out_chirho)?;
            Ok(true)
        }
        CommandChirho::CompileEffectDemoChirho { out_chirho } => {
            dag_command_chirho::compile_effect_demo_command_chirho(out_chirho)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}
