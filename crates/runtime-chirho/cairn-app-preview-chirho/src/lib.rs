// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Non-persisting preview execution for zero-capability candidate DAGs.

use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::cas_chirho;
use cairn_core_chirho::model_chirho::{DagChirho, HashChirho, NodeDefChirho};
use cairn_core_chirho::store_chirho;
use cairn_wasmtime_runner_chirho::runner_chirho;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const PREVIEW_UNREVIEWED_HEADER_CHIRHO: &str = "x-cairn-unreviewed-chirho";
pub const PREVIEW_UNREVIEWED_HEADER_VALUE_CHIRHO: &str = "true";

const NATIVE_NODE_IMPL_PREFIX_CHIRHO: &str = "native-program:";

/// The preview's policy refusals, typed so a caller can answer them without the node's name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreviewRefusalChirho {
    CapabilityBearingNodeChirho {
        node_name_chirho: String,
        capability_count_chirho: usize,
    },
    NativeProgramNodeChirho {
        node_name_chirho: String,
    },
}

impl std::fmt::Display for PreviewRefusalChirho {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapabilityBearingNodeChirho {
                node_name_chirho,
                capability_count_chirho,
            } => write!(
                f,
                "preview only accepts zero-capability DAGs; node '{node_name_chirho}' declares {capability_count_chirho} capability item(s)"
            ),
            Self::NativeProgramNodeChirho { node_name_chirho } => write!(
                f,
                "preview only accepts Tier-1 WASM DAGs; node '{node_name_chirho}' points at a native program"
            ),
        }
    }
}

impl std::error::Error for PreviewRefusalChirho {}

pub fn preview_dag_payload_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    input_chirho: &[u8],
) -> Result<Vec<u8>> {
    let dag_chirho: DagChirho = store_chirho::get_object_chirho(root_chirho, dag_hash_chirho)?;
    let mut defs_chirho = BTreeMap::new();
    for node_hash_chirho in &dag_chirho.nodes_chirho {
        let def_chirho: NodeDefChirho =
            store_chirho::get_object_chirho(root_chirho, node_hash_chirho)?;
        ensure_preview_node_allowed_chirho(&def_chirho)?;
        defs_chirho.insert(node_hash_chirho.clone(), def_chirho);
    }

    let order_chirho = topo_order_chirho(&dag_chirho)?;
    let mut outputs_chirho: BTreeMap<(HashChirho, String), Vec<u8>> = BTreeMap::new();
    for node_hash_chirho in &order_chirho {
        let def_chirho = defs_chirho
            .get(node_hash_chirho)
            .ok_or_else(|| anyhow!("node {} missing from preview defs", node_hash_chirho.0))?;
        let input_bytes_chirho = preview_node_input_chirho(
            &dag_chirho,
            node_hash_chirho,
            &outputs_chirho,
            input_chirho,
        )?;
        let output_bytes_chirho = if def_chirho.is_builtin_phi_chirho() {
            input_bytes_chirho
        } else {
            let wasm_chirho = cas_chirho::get_chirho(root_chirho, &def_chirho.impl_wasm_chirho)
                .map_err(|e_chirho| {
                    anyhow!(
                        "loading preview wasm for '{}': {e_chirho}",
                        def_chirho.name_chirho
                    )
                })?;
            runner_chirho::run_node_bytes_with_limits_chirho(
                &wasm_chirho,
                &def_chirho.entry_chirho,
                &input_bytes_chirho,
                def_chirho.fuel_limit_chirho,
                usize::try_from(def_chirho.max_output_bytes_chirho)
                    .map_err(|_| anyhow!("preview max output bytes overflow usize"))?,
                usize::try_from(def_chirho.max_memory_bytes_chirho)
                    .map_err(|_| anyhow!("preview max memory bytes overflow usize"))?,
            )?
            .output_chirho
        };
        outputs_chirho.insert(
            (node_hash_chirho.clone(), output_port_chirho(def_chirho)),
            output_bytes_chirho,
        );
    }

    let sink_chirho = sink_node_chirho(&dag_chirho)?;
    let sink_def_chirho = defs_chirho
        .get(&sink_chirho)
        .ok_or_else(|| anyhow!("preview sink {} missing from defs", sink_chirho.0))?;
    outputs_chirho
        .remove(&(sink_chirho, output_port_chirho(sink_def_chirho)))
        .ok_or_else(|| anyhow!("preview sink produced no output"))
}

fn ensure_preview_node_allowed_chirho(def_chirho: &NodeDefChirho) -> Result<()> {
    if !def_chirho.capabilities_chirho.is_empty() {
        return Err(PreviewRefusalChirho::CapabilityBearingNodeChirho {
            node_name_chirho: def_chirho.name_chirho.clone(),
            capability_count_chirho: def_chirho.capabilities_chirho.len(),
        }
        .into());
    }
    if def_chirho
        .impl_wasm_chirho
        .0
        .starts_with(NATIVE_NODE_IMPL_PREFIX_CHIRHO)
    {
        return Err(PreviewRefusalChirho::NativeProgramNodeChirho {
            node_name_chirho: def_chirho.name_chirho.clone(),
        }
        .into());
    }
    Ok(())
}

fn preview_node_input_chirho(
    dag_chirho: &DagChirho,
    node_hash_chirho: &HashChirho,
    outputs_chirho: &BTreeMap<(HashChirho, String), Vec<u8>>,
    root_input_chirho: &[u8],
) -> Result<Vec<u8>> {
    let incoming_chirho = dag_chirho
        .edges_chirho
        .iter()
        .filter(|edge_chirho| &edge_chirho.to_node_chirho == node_hash_chirho)
        .collect::<Vec<_>>();
    if incoming_chirho.is_empty() {
        return Ok(root_input_chirho.to_vec());
    }
    if incoming_chirho.len() != 1 {
        bail!(
            "preview supports exactly one live input per node; node {} has {}",
            node_hash_chirho.0,
            incoming_chirho.len()
        );
    }
    let edge_chirho = incoming_chirho[0];
    outputs_chirho
        .get(&(
            edge_chirho.from_node_chirho.clone(),
            edge_chirho.from_port_chirho.clone(),
        ))
        .cloned()
        .ok_or_else(|| anyhow!("preview input edge references missing upstream output"))
}

fn output_port_chirho(def_chirho: &NodeDefChirho) -> String {
    def_chirho
        .outputs_chirho
        .first()
        .map(|port_chirho| port_chirho.name_chirho.clone())
        .unwrap_or_else(|| "out".to_string())
}

fn topo_order_chirho(dag_chirho: &DagChirho) -> Result<Vec<HashChirho>> {
    let nodes_chirho = dag_chirho
        .nodes_chirho
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if nodes_chirho.len() != dag_chirho.nodes_chirho.len() {
        bail!("preview DAG contains duplicate node hashes");
    }
    let mut indegree_chirho = nodes_chirho
        .iter()
        .map(|node_chirho| (node_chirho.clone(), 0usize))
        .collect::<BTreeMap<_, _>>();
    let mut outgoing_chirho: BTreeMap<HashChirho, Vec<HashChirho>> = BTreeMap::new();
    for edge_chirho in &dag_chirho.edges_chirho {
        if !nodes_chirho.contains(&edge_chirho.from_node_chirho)
            || !nodes_chirho.contains(&edge_chirho.to_node_chirho)
        {
            bail!("preview DAG edge references a node outside the node list");
        }
        *indegree_chirho
            .get_mut(&edge_chirho.to_node_chirho)
            .expect("to node checked") += 1;
        outgoing_chirho
            .entry(edge_chirho.from_node_chirho.clone())
            .or_default()
            .push(edge_chirho.to_node_chirho.clone());
    }
    let mut ready_chirho = indegree_chirho
        .iter()
        .filter(|(_node_chirho, degree_chirho)| **degree_chirho == 0)
        .map(|(node_chirho, _degree_chirho)| node_chirho.clone())
        .collect::<BTreeSet<_>>();
    let mut order_chirho = Vec::new();
    while let Some(node_chirho) = ready_chirho.pop_first() {
        order_chirho.push(node_chirho.clone());
        for next_chirho in outgoing_chirho.remove(&node_chirho).unwrap_or_default() {
            let degree_chirho = indegree_chirho
                .get_mut(&next_chirho)
                .expect("outgoing target checked");
            *degree_chirho -= 1;
            if *degree_chirho == 0 {
                ready_chirho.insert(next_chirho);
            }
        }
    }
    if order_chirho.len() != nodes_chirho.len() {
        bail!("preview DAG has a cycle");
    }
    Ok(order_chirho)
}

fn sink_node_chirho(dag_chirho: &DagChirho) -> Result<HashChirho> {
    let mut sinks_chirho = dag_chirho
        .nodes_chirho
        .iter()
        .filter(|node_chirho| {
            !dag_chirho
                .edges_chirho
                .iter()
                .any(|edge_chirho| &edge_chirho.from_node_chirho == *node_chirho)
        })
        .cloned()
        .collect::<Vec<_>>();
    if sinks_chirho.len() != 1 {
        bail!("preview DAG requires exactly one sink node");
    }
    Ok(sinks_chirho.remove(0))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_core_chirho::model_chirho::{CapabilityChirho, EdgeChirho, PortChirho};
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
        std::env::temp_dir().join(format!("cairn-app-preview-test-{nanos_chirho}-{n_chirho}"))
    }

    fn store_node_chirho(
        root_chirho: &Path,
        name_chirho: &str,
        capability_chirho: Vec<CapabilityChirho>,
    ) -> HashChirho {
        let wasm_hash_chirho = cas_chirho::add_chirho(
            root_chirho,
            include_str!("../../../../examples-chirho/upcase-chirho.wat").as_bytes(),
        )
        .unwrap();
        let schema_chirho = HashChirho("bytes".to_string());
        store_chirho::put_object_chirho(
            root_chirho,
            &NodeDefChirho {
                name_chirho: name_chirho.to_string(),
                impl_wasm_chirho: wasm_hash_chirho,
                entry_chirho: "upcase_chirho".to_string(),
                inputs_chirho: vec![PortChirho {
                    name_chirho: "in".to_string(),
                    schema_chirho: schema_chirho.clone(),
                }],
                outputs_chirho: vec![PortChirho {
                    name_chirho: "out".to_string(),
                    schema_chirho,
                }],
                capabilities_chirho: capability_chirho,
                fuel_limit_chirho: 1_000_000,
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn preview_pure_wasm_dag_without_writing_runtime_surfaces_chirho() {
        let root_chirho = tmp_root_chirho();
        let node_chirho = store_node_chirho(&root_chirho, "preview_pure_chirho", Vec::new());
        let dag_chirho = store_chirho::put_object_chirho(
            &root_chirho,
            &DagChirho {
                nodes_chirho: vec![node_chirho],
                edges_chirho: Vec::new(),
            },
        )
        .unwrap();
        let before_files_chirho = file_count_chirho(&root_chirho);
        let output_chirho =
            preview_dag_payload_chirho(&root_chirho, &dag_chirho, b"hello preview").unwrap();
        assert_eq!(output_chirho, b"HELLO PREVIEW");
        assert_eq!(file_count_chirho(&root_chirho), before_files_chirho);
        assert!(!root_chirho.join("effects-chirho").exists());
        assert!(!root_chirho.join("runkeys-chirho").exists());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn preview_rejects_capability_dag_before_runtime_persistence_chirho() {
        let root_chirho = tmp_root_chirho();
        let node_chirho = store_node_chirho(
            &root_chirho,
            "preview_write_chirho",
            vec![CapabilityChirho::WriteStoreChirho {
                prefix_chirho: "preview-write-chirho".to_string(),
            }],
        );
        let dag_chirho = store_chirho::put_object_chirho(
            &root_chirho,
            &DagChirho {
                nodes_chirho: vec![node_chirho],
                edges_chirho: Vec::new(),
            },
        )
        .unwrap();
        let before_files_chirho = file_count_chirho(&root_chirho);
        let err_chirho =
            preview_dag_payload_chirho(&root_chirho, &dag_chirho, b"secret").unwrap_err();
        assert!(err_chirho.to_string().contains("zero-capability DAGs"));
        assert_eq!(file_count_chirho(&root_chirho), before_files_chirho);
        assert!(!root_chirho.join("effects-chirho").exists());
        assert!(!root_chirho.join("refs-chirho.json").exists());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn preview_runs_simple_pure_edge_chain_chirho() {
        let root_chirho = tmp_root_chirho();
        let first_chirho = store_node_chirho(&root_chirho, "preview_first_chirho", Vec::new());
        let second_chirho = store_node_chirho(&root_chirho, "preview_second_chirho", Vec::new());
        let dag_chirho = store_chirho::put_object_chirho(
            &root_chirho,
            &DagChirho {
                nodes_chirho: vec![first_chirho.clone(), second_chirho.clone()],
                edges_chirho: vec![EdgeChirho {
                    from_node_chirho: first_chirho,
                    from_port_chirho: "out".to_string(),
                    to_node_chirho: second_chirho,
                    to_port_chirho: "in".to_string(),
                    privacy_chirho: None,
                }],
            },
        )
        .unwrap();
        let output_chirho =
            preview_dag_payload_chirho(&root_chirho, &dag_chirho, b"chain").unwrap();
        assert_eq!(output_chirho, b"CHAIN");
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    fn file_count_chirho(root_chirho: &Path) -> usize {
        fn walk_chirho(path_chirho: &Path, total_chirho: &mut usize) {
            if let Ok(entries_chirho) = std::fs::read_dir(path_chirho) {
                for entry_chirho in entries_chirho.flatten() {
                    let path_chirho = entry_chirho.path();
                    if path_chirho.is_dir() {
                        walk_chirho(&path_chirho, total_chirho);
                    } else {
                        *total_chirho += 1;
                    }
                }
            }
        }
        let mut total_chirho = 0;
        walk_chirho(root_chirho, &mut total_chirho);
        total_chirho
    }
}
