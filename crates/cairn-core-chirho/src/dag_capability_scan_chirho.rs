// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Collects the distinct capabilities of a stored DAG's nodes.
//!
//! It lived in `governance_flows_chirho/review_chirho` and moved here because it has **no root
//! dependencies at all**: every type and function it touches (`DagChirho`, `NodeDefChirho`,
//! `CapabilityChirho`, `store_chirho::get_object_chirho`) already lives in this crate. It also has
//! three consumers in two different root pillars plus the CLI, and a function used by three pillars
//! belongs below all of them rather than inside any one. Root re-exports it, so the CLI reaches it
//! through the path it already depends on.

use crate::model_chirho::{CapabilityChirho, DagChirho, HashChirho, NodeDefChirho};
use crate::store_chirho;
use anyhow::{Context, Result};
use std::path::Path;

/// Every capability any node of `dag_chirho` declares, deduplicated, in first-seen order.
///
/// Answers "what can this DAG do?" from the content-addressed objects alone — no refs, no logs, no
/// signatures. A DAG whose nodes declare nothing comes back empty, which is the pure case.
pub fn collect_dag_capabilities_chirho(
    root_chirho: &Path,
    dag_chirho: &HashChirho,
) -> Result<Vec<CapabilityChirho>> {
    let dag_obj_chirho: DagChirho = store_chirho::get_object_chirho(root_chirho, dag_chirho)
        .with_context(|| format!("capability scan DAG {} is not in the store", dag_chirho.0))?;
    let mut capabilities_chirho: Vec<CapabilityChirho> = Vec::new();
    for node_chirho in &dag_obj_chirho.nodes_chirho {
        let node_def_chirho: NodeDefChirho =
            store_chirho::get_object_chirho(root_chirho, node_chirho).with_context(|| {
                format!(
                    "DAG {} node {} is not a NodeDefChirho",
                    dag_chirho.0, node_chirho.0
                )
            })?;
        for capability_chirho in &node_def_chirho.capabilities_chirho {
            if !capabilities_chirho.contains(capability_chirho) {
                capabilities_chirho.push(capability_chirho.clone());
            }
        }
    }
    Ok(capabilities_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A unique scratch store root under the OS temp dir.
    fn tmp_root_chirho() -> std::path::PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!(
            "cairn-dag-capability-scan-test-{nanos_chirho}-{n_chirho}"
        ))
    }

    fn store_node_chirho(
        root_chirho: &Path,
        name_chirho: &str,
        capabilities_chirho: Vec<CapabilityChirho>,
    ) -> HashChirho {
        let node_chirho = NodeDefChirho {
            name_chirho: name_chirho.to_string(),
            capabilities_chirho,
            ..Default::default()
        };
        store_chirho::put_object_chirho(root_chirho, &node_chirho).expect("store node")
    }

    fn store_dag_chirho(root_chirho: &Path, nodes_chirho: Vec<HashChirho>) -> HashChirho {
        let dag_chirho = DagChirho {
            nodes_chirho,
            edges_chirho: Vec::new(),
        };
        store_chirho::put_object_chirho(root_chirho, &dag_chirho).expect("store dag")
    }

    fn write_store_chirho(prefix_chirho: &str) -> CapabilityChirho {
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: prefix_chirho.to_string(),
        }
    }

    #[test]
    fn a_capability_repeated_across_nodes_is_collected_once_in_first_seen_order_chirho() {
        let root_chirho = tmp_root_chirho();
        let paid_chirho = CapabilityChirho::PaidEffectChirho {
            effect_chirho: "send_crm_email_chirho".to_string(),
            caller_chirho: "owner/x".to_string(),
        };
        // Node A declares write-then-paid; node B repeats the write. The distinct set must be the
        // two, in the order A declared them -- order is part of the contract, since callers render
        // this list to a human.
        let node_a_chirho = store_node_chirho(
            &root_chirho,
            "writer",
            vec![write_store_chirho("contact/"), paid_chirho.clone()],
        );
        let node_b_chirho = store_node_chirho(
            &root_chirho,
            "writer-again",
            vec![write_store_chirho("contact/")],
        );
        let dag_chirho = store_dag_chirho(&root_chirho, vec![node_a_chirho, node_b_chirho]);

        let collected_chirho =
            collect_dag_capabilities_chirho(&root_chirho, &dag_chirho).expect("scan the DAG");
        assert_eq!(
            collected_chirho,
            vec![write_store_chirho("contact/"), paid_chirho],
            "the duplicate collapses and first-seen order survives"
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn a_dag_whose_nodes_declare_nothing_scans_empty_chirho() {
        let root_chirho = tmp_root_chirho();
        let pure_chirho = store_node_chirho(&root_chirho, "pure", Vec::new());
        let dag_chirho = store_dag_chirho(&root_chirho, vec![pure_chirho]);

        assert!(
            collect_dag_capabilities_chirho(&root_chirho, &dag_chirho)
                .expect("scan the DAG")
                .is_empty(),
            "a capability-free DAG is the pure case and must scan to nothing"
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn a_dag_that_is_not_in_the_store_is_refused_rather_than_scanning_empty_chirho() {
        // The distinction that matters: "this DAG declares no capabilities" and "this DAG is not
        // here" must not both come back as an empty list, or an absent DAG reads as a pure one.
        let root_chirho = tmp_root_chirho();
        let error_chirho = collect_dag_capabilities_chirho(
            &root_chirho,
            &HashChirho("deadbeef-not-stored-chirho".to_string()),
        )
        .expect_err("an absent DAG must be refused, never scanned as empty")
        .to_string();
        assert!(
            error_chirho.contains("is not in the store"),
            "the refusal must name the missing DAG, not some incidental failure: {error_chirho}"
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
