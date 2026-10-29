// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Core demo CLI helpers split out of dispatch_chirho.rs.

use crate::args_chirho::CommandChirho;
use cairn_chirho::model_chirho::{CapabilityChirho, DagChirho, EdgeChirho};
use cairn_chirho::{app_chirho, store_chirho};
use cairn_dag_command_chirho::{
    build_bytes_node_chirho, build_effect_node_chirho, ensure_demo_owner_chirho,
};
use std::path::Path;

pub(crate) fn handle_demo_command_chirho(
    root_chirho: &Path,
    command_chirho: CommandChirho,
) -> anyhow::Result<Option<CommandChirho>> {
    match command_chirho {
        CommandChirho::CounterDemoChirho => {
            const INC_WAT_CHIRHO: &str =
                include_str!("../../../../../examples-chirho/inc-u64-chirho.wat");
            let (_read_def_chirho, read_hash_chirho) = build_effect_node_chirho(
                root_chirho,
                "read_count_chirho",
                CapabilityChirho::ReadStoreChirho {
                    prefix_chirho: "count".to_string(),
                },
            )?;
            let (_inc_def_chirho, inc_hash_chirho) = build_bytes_node_chirho(
                root_chirho,
                "inc_u64_chirho",
                INC_WAT_CHIRHO.as_bytes(),
                "inc_u64_chirho",
            )?;
            let (_write_def_chirho, write_hash_chirho) = build_effect_node_chirho(
                root_chirho,
                "write_count_chirho",
                CapabilityChirho::WriteStoreChirho {
                    prefix_chirho: "count".to_string(),
                },
            )?;
            let dag_obj_chirho = DagChirho {
                nodes_chirho: vec![
                    read_hash_chirho.clone(),
                    inc_hash_chirho.clone(),
                    write_hash_chirho.clone(),
                ],
                edges_chirho: vec![
                    EdgeChirho {
                        from_node_chirho: read_hash_chirho,
                        from_port_chirho: "out".to_string(),
                        to_node_chirho: inc_hash_chirho.clone(),
                        to_port_chirho: "in".to_string(),
                        privacy_chirho: None,
                    },
                    EdgeChirho {
                        from_node_chirho: inc_hash_chirho,
                        from_port_chirho: "out".to_string(),
                        to_node_chirho: write_hash_chirho,
                        to_port_chirho: "in".to_string(),
                        privacy_chirho: None,
                    },
                ],
            };
            let dag_hash_chirho = store_chirho::put_object_chirho(root_chirho, &dag_obj_chirho)?;
            let owner_chirho = ensure_demo_owner_chirho(root_chirho, "counter")?;
            app_chirho::deploy_app_chirho(
                root_chirho,
                "counter",
                dag_hash_chirho.clone(),
                &owner_chirho,
            )?;
            println!(
                "deployed counter -> dag {} owner={}  (POST /app-chirho/counter to increment)",
                dag_hash_chirho.0, owner_chirho
            );
            Ok(None)
        }
        CommandChirho::SsrDemoChirho { key_chirho } => {
            // A single-node browser DAG: read(<key>) is both source and sink; its value is the
            // body. /ssr-chirho/<key> lowers it to an HTML document server-side.
            let (_read_def_chirho, read_hash_chirho) = build_effect_node_chirho(
                root_chirho,
                "read_chirho",
                CapabilityChirho::ReadStoreChirho {
                    prefix_chirho: key_chirho.clone(),
                },
            )?;
            let dag_obj_chirho = DagChirho {
                nodes_chirho: vec![read_hash_chirho],
                edges_chirho: vec![],
            };
            let dag_hash_chirho = store_chirho::put_object_chirho(root_chirho, &dag_obj_chirho)?;
            let owner_chirho = ensure_demo_owner_chirho(root_chirho, &key_chirho)?;
            app_chirho::deploy_app_chirho(
                root_chirho,
                &key_chirho,
                dag_hash_chirho.clone(),
                &owner_chirho,
            )?;
            app_chirho::set_app_input_policy_chirho(
                root_chirho,
                &key_chirho,
                None,
                &owner_chirho,
                app_chirho::AppInputModeChirho::PlainChirho,
            )?;
            println!(
                "deployed SSR app '{key_chirho}' -> dag {} owner={}  (GET /ssr-chirho/{key_chirho})",
                dag_hash_chirho.0,
                owner_chirho
            );
            Ok(None)
        }
        other_chirho => Ok(Some(other_chirho)),
    }
}
