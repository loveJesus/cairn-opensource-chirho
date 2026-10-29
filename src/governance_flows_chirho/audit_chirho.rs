// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Audit — walk the provenance DAG behind a run.
//!
//! A `RunResultChirho` records its `parents_chirho` (the upstream runs that produced its
//! inputs) and its `effects_chirho` (the signed, logged side effects). Auditing follows that
//! chain depth-first, answering "what happened, from what, by what code" for any output.
//!
//! Volatile effect nodes (live reads) do not persist a `RunResultChirho`, so an ancestor may
//! legitimately be absent — the walk records it as "not stored" rather than failing.

use crate::cache_chirho;
use crate::model_chirho::{HashChirho, RunResultChirho};
use anyhow::{anyhow, Result};
use std::collections::HashSet;
use std::path::Path;

/// One node in the provenance walk: its depth from the queried run, the run id, and the run
/// result (None if it was not persisted, e.g. a volatile read).
pub struct AuditEntryChirho {
    pub depth_chirho: usize,
    pub run_chirho: HashChirho,
    pub result_chirho: Option<RunResultChirho>,
}

/// Walk the provenance DAG from `run_hash` through `parents`, depth-first and deduplicated.
/// Returns entries in visit order (the queried run first, then its ancestors). Errors only if
/// the queried run itself is absent.
pub fn audit_chirho(
    root_chirho: &Path,
    run_hash_chirho: &HashChirho,
) -> Result<Vec<AuditEntryChirho>> {
    if cache_chirho::load_result_chirho(root_chirho, run_hash_chirho)?.is_none() {
        return Err(anyhow!("no run {} in the store", run_hash_chirho.0));
    }
    let mut out_chirho = Vec::new();
    let mut seen_chirho = HashSet::new();
    walk_chirho(
        root_chirho,
        run_hash_chirho,
        0,
        &mut seen_chirho,
        &mut out_chirho,
    )?;
    Ok(out_chirho)
}

fn walk_chirho(
    root_chirho: &Path,
    run_hash_chirho: &HashChirho,
    depth_chirho: usize,
    seen_chirho: &mut HashSet<HashChirho>,
    out_chirho: &mut Vec<AuditEntryChirho>,
) -> Result<()> {
    if !seen_chirho.insert(run_hash_chirho.clone()) {
        return Ok(()); // already visited (shared ancestor)
    }
    match cache_chirho::load_result_chirho(root_chirho, run_hash_chirho)? {
        Some(result_chirho) => {
            let parents_chirho = result_chirho.parents_chirho.clone();
            out_chirho.push(AuditEntryChirho {
                depth_chirho,
                run_chirho: run_hash_chirho.clone(),
                result_chirho: Some(result_chirho),
            });
            for parent_chirho in &parents_chirho {
                walk_chirho(
                    root_chirho,
                    parent_chirho,
                    depth_chirho + 1,
                    seen_chirho,
                    out_chirho,
                )?;
            }
        }
        None => out_chirho.push(AuditEntryChirho {
            depth_chirho,
            run_chirho: run_hash_chirho.clone(),
            result_chirho: None,
        }),
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::model_chirho::{DagChirho, EdgeChirho, NodeDefChirho, PortChirho};
    use crate::{cas_chirho, dag_chirho, store_chirho};
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
        std::env::temp_dir().join(format!("cairn-audit-test-{nanos_chirho}-{n_chirho}"))
    }

    fn store_pure_node_chirho(
        root_chirho: &Path,
        name_chirho: &str,
        wat_chirho: &str,
        entry_chirho: &str,
    ) -> HashChirho {
        let impl_hash_chirho = cas_chirho::add_chirho(root_chirho, wat_chirho.as_bytes()).unwrap();
        let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
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
            fuel_limit_chirho: 1_000_000,
            ..Default::default()
        };
        store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap()
    }

    #[test]
    fn audit_walks_provenance_chirho() {
        let root_chirho = tmp_root_chirho();
        let upcase_wat_chirho = include_str!("../../examples-chirho/upcase-chirho.wat");
        let reverse_wat_chirho = include_str!("../../examples-chirho/reverse-chirho.wat");
        let u_hash_chirho = store_pure_node_chirho(
            &root_chirho,
            "upcase_chirho",
            upcase_wat_chirho,
            "upcase_chirho",
        );
        let r_hash_chirho = store_pure_node_chirho(
            &root_chirho,
            "reverse_chirho",
            reverse_wat_chirho,
            "reverse_chirho",
        );

        let dag_obj_chirho = DagChirho {
            nodes_chirho: vec![u_hash_chirho.clone(), r_hash_chirho.clone()],
            edges_chirho: vec![EdgeChirho {
                from_node_chirho: u_hash_chirho,
                from_port_chirho: "out".to_string(),
                to_node_chirho: r_hash_chirho,
                to_port_chirho: "in".to_string(),
                privacy_chirho: None,
            }],
        };
        let report_chirho =
            dag_chirho::run_dag_chirho(&root_chirho, &dag_obj_chirho, b"hello").unwrap();

        // Audit the sink (reverse) run -> chain is [reverse @0, upcase @1].
        let sink_run_chirho = &report_chirho.node_runs_chirho[1].run_chirho;
        let chain_chirho = audit_chirho(&root_chirho, sink_run_chirho).unwrap();
        assert_eq!(chain_chirho.len(), 2);
        assert_eq!(chain_chirho[0].depth_chirho, 0);
        assert_eq!(chain_chirho[1].depth_chirho, 1);
        assert!(chain_chirho[0].result_chirho.is_some());
        assert_eq!(
            &chain_chirho[1].run_chirho,
            &report_chirho.node_runs_chirho[0].run_chirho
        );

        // A missing run errors.
        assert!(audit_chirho(&root_chirho, &HashChirho("deadbeef".to_string())).is_err());

        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
