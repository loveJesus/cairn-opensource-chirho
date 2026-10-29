// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Graph — render a DagChirho as a readable graph (Mermaid or Graphviz DOT): nodes labelled with
//! their name + purity/effect kind, edges labelled with the port wiring. The observability "see
//! the DAG connections" view (M9.1).

use crate::model_chirho::{DagChirho, NodeDefChirho};
use crate::{blessed_chirho, store_chirho};
use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;

/// A node label: `name (pure)` or `name (effect: kind,kind)`.
fn node_label_chirho(def_chirho: &NodeDefChirho) -> String {
    if def_chirho.is_pure_chirho() {
        format!("{} (pure)", def_chirho.name_chirho)
    } else {
        let kinds_chirho: Vec<&str> = def_chirho
            .capabilities_chirho
            .iter()
            .map(blessed_chirho::capability_kind_chirho)
            .collect();
        format!(
            "{} (effect: {})",
            def_chirho.name_chirho,
            kinds_chirho.join(",")
        )
    }
}

/// Map each node hash to a stable `nN` id (by position in the DAG).
fn ids_chirho(dag_chirho: &DagChirho) -> HashMap<String, usize> {
    dag_chirho
        .nodes_chirho
        .iter()
        .enumerate()
        .map(|(i_chirho, hash_chirho)| (hash_chirho.0.clone(), i_chirho))
        .collect()
}

/// Render the DAG as a Mermaid flowchart (renders in GitHub, many markdown viewers, etc.).
pub fn dag_to_mermaid_chirho(root_chirho: &Path, dag_chirho: &DagChirho) -> Result<String> {
    let id_of_chirho = ids_chirho(dag_chirho);
    let mut out_chirho = String::from("flowchart TD\n");
    for (i_chirho, hash_chirho) in dag_chirho.nodes_chirho.iter().enumerate() {
        let def_chirho: NodeDefChirho = store_chirho::get_object_chirho(root_chirho, hash_chirho)?;
        out_chirho.push_str(&format!(
            "  n{i_chirho}[\"{}\"]\n",
            node_label_chirho(&def_chirho)
        ));
    }
    for edge_chirho in &dag_chirho.edges_chirho {
        if let (Some(from_chirho), Some(to_chirho)) = (
            id_of_chirho.get(&edge_chirho.from_node_chirho.0),
            id_of_chirho.get(&edge_chirho.to_node_chirho.0),
        ) {
            out_chirho.push_str(&format!(
                "  n{from_chirho} -->|{}→{}| n{to_chirho}\n",
                edge_chirho.from_port_chirho, edge_chirho.to_port_chirho
            ));
        }
    }
    Ok(out_chirho)
}

/// Render the DAG as Graphviz DOT (pipe to `dot -Tsvg`).
pub fn dag_to_dot_chirho(root_chirho: &Path, dag_chirho: &DagChirho) -> Result<String> {
    let id_of_chirho = ids_chirho(dag_chirho);
    let mut out_chirho =
        String::from("digraph cairn_chirho {\n  rankdir=TB;\n  node [shape=box];\n");
    for (i_chirho, hash_chirho) in dag_chirho.nodes_chirho.iter().enumerate() {
        let def_chirho: NodeDefChirho = store_chirho::get_object_chirho(root_chirho, hash_chirho)?;
        out_chirho.push_str(&format!(
            "  n{i_chirho} [label=\"{}\"];\n",
            node_label_chirho(&def_chirho)
        ));
    }
    for edge_chirho in &dag_chirho.edges_chirho {
        if let (Some(from_chirho), Some(to_chirho)) = (
            id_of_chirho.get(&edge_chirho.from_node_chirho.0),
            id_of_chirho.get(&edge_chirho.to_node_chirho.0),
        ) {
            out_chirho.push_str(&format!(
                "  n{from_chirho} -> n{to_chirho} [label=\"{}->{}\"];\n",
                edge_chirho.from_port_chirho, edge_chirho.to_port_chirho
            ));
        }
    }
    out_chirho.push_str("}\n");
    Ok(out_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::cas_chirho;
    use crate::model_chirho::{EdgeChirho, HashChirho, PortChirho};
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
        std::env::temp_dir().join(format!("cairn-graph-test-{nanos_chirho}-{n_chirho}"))
    }

    fn mk_node_chirho(root_chirho: &Path, wat_chirho: &str, name_chirho: &str) -> HashChirho {
        let impl_chirho = cas_chirho::add_chirho(root_chirho, wat_chirho.as_bytes()).unwrap();
        let schema_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
        let def_chirho = NodeDefChirho {
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
            capabilities_chirho: vec![],
            fuel_limit_chirho: 1_000_000,
            ..Default::default()
        };
        store_chirho::put_object_chirho(root_chirho, &def_chirho).unwrap()
    }

    #[test]
    fn renders_mermaid_with_nodes_and_edge_chirho() {
        let root_chirho = tmp_root_chirho();
        let upcase_chirho = mk_node_chirho(
            &root_chirho,
            include_str!("../../examples-chirho/upcase-chirho.wat"),
            "upcase_chirho",
        );
        let reverse_chirho = mk_node_chirho(
            &root_chirho,
            include_str!("../../examples-chirho/reverse-chirho.wat"),
            "reverse_chirho",
        );
        let dag_chirho = DagChirho {
            nodes_chirho: vec![upcase_chirho.clone(), reverse_chirho.clone()],
            edges_chirho: vec![EdgeChirho {
                from_node_chirho: upcase_chirho,
                from_port_chirho: "out".to_string(),
                to_node_chirho: reverse_chirho,
                to_port_chirho: "in".to_string(),
                privacy_chirho: None,
            }],
        };
        let mermaid_chirho = dag_to_mermaid_chirho(&root_chirho, &dag_chirho).unwrap();
        assert!(mermaid_chirho.contains("flowchart TD"));
        assert!(mermaid_chirho.contains("upcase_chirho (pure)"));
        assert!(mermaid_chirho.contains("reverse_chirho (pure)"));
        assert!(mermaid_chirho.contains("n0 -->"));
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
