// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Builds stored DAG descriptors from author-supplied node hashes and edge specs.

use anyhow::{anyhow, bail, Context, Result};
use cairn_core_chirho::model_chirho::{
    DagChirho, EdgeChirho, EdgePrivacyChirho, HashChirho, NodeDefChirho, PortChirho,
};
use cairn_core_chirho::store_chirho;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DagBuildInputChirho {
    pub nodes_chirho: Vec<HashChirho>,
    pub edges_chirho: Vec<DagBuildEdgeInputChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DagBuildEdgeInputChirho {
    pub from_node_chirho: HashChirho,
    pub from_port_chirho: String,
    pub to_node_chirho: HashChirho,
    pub to_port_chirho: String,
    pub privacy_chirho: Option<EdgePrivacyChirho>,
}

pub fn build_dag_chirho(
    root_chirho: &Path,
    input_chirho: DagBuildInputChirho,
) -> Result<(DagChirho, HashChirho)> {
    if input_chirho.nodes_chirho.is_empty() {
        bail!("dag-build requires at least one --node");
    }

    let mut node_defs_chirho = BTreeMap::new();
    for node_chirho in &input_chirho.nodes_chirho {
        if node_defs_chirho.contains_key(node_chirho) {
            bail!("duplicate DAG node {}", node_chirho.0);
        }
        let node_def_chirho: NodeDefChirho =
            store_chirho::get_object_chirho(root_chirho, node_chirho).with_context(|| {
                format!("DAG node {} is not a stored NodeDefChirho", node_chirho.0)
            })?;
        node_defs_chirho.insert(node_chirho.clone(), node_def_chirho);
    }

    let mut seen_edges_chirho = BTreeSet::new();
    let mut edges_chirho = Vec::new();
    for edge_chirho in input_chirho.edges_chirho {
        let from_def_chirho = node_defs_chirho
            .get(&edge_chirho.from_node_chirho)
            .ok_or_else(|| {
                anyhow!(
                    "edge source node {} is not in --node set",
                    edge_chirho.from_node_chirho.0
                )
            })?;
        let to_def_chirho = node_defs_chirho
            .get(&edge_chirho.to_node_chirho)
            .ok_or_else(|| {
                anyhow!(
                    "edge target node {} is not in --node set",
                    edge_chirho.to_node_chirho.0
                )
            })?;
        if !port_exists_chirho(
            &from_def_chirho.outputs_chirho,
            &edge_chirho.from_port_chirho,
        ) {
            bail!(
                "edge source port {}:{} is not an output port",
                edge_chirho.from_node_chirho.0,
                edge_chirho.from_port_chirho
            );
        }
        if !port_exists_chirho(&to_def_chirho.inputs_chirho, &edge_chirho.to_port_chirho) {
            bail!(
                "edge target port {}:{} is not an input port",
                edge_chirho.to_node_chirho.0,
                edge_chirho.to_port_chirho
            );
        }
        let key_chirho = (
            edge_chirho.from_node_chirho.clone(),
            edge_chirho.from_port_chirho.clone(),
            edge_chirho.to_node_chirho.clone(),
            edge_chirho.to_port_chirho.clone(),
        );
        if !seen_edges_chirho.insert(key_chirho) {
            bail!("duplicate DAG edge");
        }
        edges_chirho.push(EdgeChirho {
            from_node_chirho: edge_chirho.from_node_chirho,
            from_port_chirho: edge_chirho.from_port_chirho,
            to_node_chirho: edge_chirho.to_node_chirho,
            to_port_chirho: edge_chirho.to_port_chirho,
            privacy_chirho: edge_chirho.privacy_chirho,
        });
    }

    let dag_chirho = DagChirho {
        nodes_chirho: input_chirho.nodes_chirho,
        edges_chirho,
    };
    let dag_hash_chirho = store_chirho::put_object_chirho(root_chirho, &dag_chirho)?;
    Ok((dag_chirho, dag_hash_chirho))
}

pub fn parse_dag_edge_spec_chirho(spec_chirho: &str) -> Result<DagBuildEdgeInputChirho> {
    let (from_chirho, to_chirho) = spec_chirho.split_once('=').ok_or_else(|| {
        anyhow!("DAG edge '{spec_chirho}' must be from_node:from_port=to_node:to_port")
    })?;
    let (from_node_chirho, from_port_chirho) = parse_node_port_chirho(from_chirho, spec_chirho)?;
    let (to_node_chirho, to_port_chirho) = parse_node_port_chirho(to_chirho, spec_chirho)?;
    Ok(DagBuildEdgeInputChirho {
        from_node_chirho,
        from_port_chirho,
        to_node_chirho,
        to_port_chirho,
        privacy_chirho: None,
    })
}

fn parse_node_port_chirho(value_chirho: &str, spec_chirho: &str) -> Result<(HashChirho, String)> {
    let (node_chirho, port_chirho) = value_chirho.split_once(':').ok_or_else(|| {
        anyhow!("DAG edge '{spec_chirho}' must be from_node:from_port=to_node:to_port")
    })?;
    if node_chirho.trim().is_empty() || port_chirho.trim().is_empty() || port_chirho.contains(':') {
        bail!("DAG edge '{spec_chirho}' must be from_node:from_port=to_node:to_port");
    }
    Ok((HashChirho(node_chirho.to_string()), port_chirho.to_string()))
}

fn port_exists_chirho(ports_chirho: &[PortChirho], name_chirho: &str) -> bool {
    ports_chirho
        .iter()
        .any(|port_chirho| port_chirho.name_chirho == name_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_core_chirho::model_chirho::CapabilityChirho;
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
        std::env::temp_dir().join(format!("cairn-dag-author-test-{nanos_chirho}-{n_chirho}"))
    }

    fn store_node_chirho(root_chirho: &Path, name_chirho: &str) -> HashChirho {
        let schema_chirho = store_chirho::put_object_chirho(root_chirho, &"bytes").unwrap();
        let impl_chirho =
            store_chirho::put_object_chirho(root_chirho, &format!("{name_chirho}-wasm")).unwrap();
        let node_chirho = NodeDefChirho {
            name_chirho: name_chirho.to_string(),
            impl_wasm_chirho: impl_chirho,
            entry_chirho: name_chirho.to_string(),
            inputs_chirho: vec![PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: schema_chirho.clone(),
            }],
            outputs_chirho: vec![PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho,
            }],
            capabilities_chirho: Vec::<CapabilityChirho>::new(),
            effect_contract_set_chirho: None,
            fuel_limit_chirho: 1_000_000,
            max_output_bytes_chirho:
                cairn_core_chirho::model_chirho::DEFAULT_NODE_MAX_OUTPUT_BYTES_CHIRHO,
            max_memory_bytes_chirho:
                cairn_core_chirho::model_chirho::DEFAULT_NODE_MAX_MEMORY_BYTES_CHIRHO,
        };
        store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap()
    }

    #[test]
    fn dag_build_stores_single_node_dag_chirho() {
        let root_chirho = tmp_root_chirho();
        let node_chirho = store_node_chirho(&root_chirho, "contact_chirho");

        let (_dag_chirho, dag_hash_chirho) = build_dag_chirho(
            &root_chirho,
            DagBuildInputChirho {
                nodes_chirho: vec![node_chirho.clone()],
                edges_chirho: Vec::new(),
            },
        )
        .unwrap();
        let stored_chirho: DagChirho =
            store_chirho::get_object_chirho(&root_chirho, &dag_hash_chirho).unwrap();
        assert_eq!(stored_chirho.nodes_chirho, vec![node_chirho]);
        assert!(stored_chirho.edges_chirho.is_empty());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn dag_build_rejects_bad_edge_ports_chirho() {
        let root_chirho = tmp_root_chirho();
        let from_chirho = store_node_chirho(&root_chirho, "from_chirho");
        let to_chirho = store_node_chirho(&root_chirho, "to_chirho");

        let err_chirho = build_dag_chirho(
            &root_chirho,
            DagBuildInputChirho {
                nodes_chirho: vec![from_chirho.clone(), to_chirho.clone()],
                edges_chirho: vec![DagBuildEdgeInputChirho {
                    from_node_chirho: from_chirho,
                    from_port_chirho: "missing".to_string(),
                    to_node_chirho: to_chirho,
                    to_port_chirho: "in".to_string(),
                    privacy_chirho: None,
                }],
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err_chirho.contains("not an output port"));
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn parses_dag_edge_spec_chirho() {
        let spec_chirho = format!("{}:out={}:in", "a".repeat(64), "b".repeat(64));
        let edge_chirho = parse_dag_edge_spec_chirho(&spec_chirho).unwrap();
        assert_eq!(edge_chirho.from_port_chirho, "out");
        assert_eq!(edge_chirho.to_port_chirho, "in");
    }
}
