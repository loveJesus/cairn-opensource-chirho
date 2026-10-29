// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! cairn-runtime-core — the **portable** DAG executor, over the ports only. Wasm-safe: depends on
//! `cairn-core` (model types + port traits) and nothing concrete (no fs/redb/wasmtime). It runs a
//! DAG by reading inputs through `ContentStoreChirho`, executing each node through
//! `NodeRunnerChirho`, storing outputs back, and appending a typed provenance record through
//! `AuditLogChirho`.
//!
//! M35.3 scope (deliberately the minimal vertical slice — see CRATE-SPLIT-PLAN §M35): a **linear**
//! chain of single-input/single-output nodes; each node's output feeds the next. NOT the full
//! `dag_chirho` executor — no cache/`RunKey`, no effects, no billing, no wasmtime. Multi-port
//! fan-in/out and those concerns are later bricks.
//!
//! M35.6a adds an ADDITIVE async sibling executor `run_linear_dag_async_chirho` over the async ports
//! (`ContentStoreAsyncChirho` / `AuditLogAsyncChirho`), for browser backends whose I/O is async
//! (IndexedDB). The sync path is unchanged; a `SyncAsAsyncChirho` bridge proves the two are
//! byte-identical natively. NodeRunner stays sync.

use anyhow::{anyhow, Result};
use cairn_core_chirho::cas_chirho::hash_chirho;
use cairn_core_chirho::model_chirho::{DagChirho, HashChirho, NodeDefChirho};
use cairn_core_chirho::ports_chirho::{
    AuditLogAsyncChirho, AuditLogChirho, ContentStoreAsyncChirho, ContentStoreChirho,
    EffectOutcomeChirho, EffectPerformerChirho, EffectRecordChirho, NodeRunnerChirho,
    EFFECT_RECORD_SCHEMA_CHIRHO,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};

/// Schema tag for the executor's provenance record (hashed into the audit log).
pub const RUNTIME_NODE_RUN_SCHEMA_CHIRHO: &str = "runtime-node-run-v1";

/// One node execution's provenance: which node ran, on what input, producing what output. Typed
/// (not an ad-hoc blob) + schema-tagged so a future format change yields different hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RuntimeNodeRunChirho {
    pub schema_chirho: String,
    pub node_chirho: HashChirho,
    pub input_hash_chirho: HashChirho,
    pub output_hash_chirho: HashChirho,
}

impl RuntimeNodeRunChirho {
    pub fn new_chirho(
        node_chirho: HashChirho,
        input_hash_chirho: HashChirho,
        output_hash_chirho: HashChirho,
    ) -> Self {
        Self {
            schema_chirho: RUNTIME_NODE_RUN_SCHEMA_CHIRHO.to_string(),
            node_chirho,
            input_hash_chirho,
            output_hash_chirho,
        }
    }
}

/// The outcome of running a DAG: the final output's content hash and the audit chain's new head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagRunResultChirho {
    pub output_hash_chirho: HashChirho,
    pub audit_head_chirho: HashChirho,
}

/// Resolve a `NodeDefChirho` from the content store by its hash (node defs are content-addressed).
fn load_node_chirho<C: ContentStoreChirho>(
    store_chirho: &C,
    node_hash_chirho: &HashChirho,
) -> Result<NodeDefChirho> {
    let bytes_chirho = store_chirho
        .get_chirho(node_hash_chirho)?
        .ok_or_else(|| anyhow!("node {} not in content store", node_hash_chirho.0))?;
    Ok(serde_json::from_slice(&bytes_chirho)?)
}

/// Kahn topological order of the DAG's nodes. Deterministic (node + edge declaration order), so the
/// same DAG yields the same order on every backend. Errors on a cycle or dangling edge.
fn topo_order_chirho(dag_chirho: &DagChirho) -> Result<Vec<HashChirho>> {
    let mut indegree_chirho: BTreeMap<HashChirho, usize> = dag_chirho
        .nodes_chirho
        .iter()
        .cloned()
        .map(|n| (n, 0))
        .collect();
    for edge_chirho in &dag_chirho.edges_chirho {
        match indegree_chirho.get_mut(&edge_chirho.to_node_chirho) {
            Some(degree_chirho) => *degree_chirho += 1,
            None => {
                return Err(anyhow!(
                    "edge to unknown node {}",
                    edge_chirho.to_node_chirho.0
                ))
            }
        }
    }
    let mut queue_chirho: VecDeque<HashChirho> = dag_chirho
        .nodes_chirho
        .iter()
        .filter(|n| indegree_chirho.get(*n) == Some(&0))
        .cloned()
        .collect();
    let mut order_chirho: Vec<HashChirho> = Vec::new();
    while let Some(node_chirho) = queue_chirho.pop_front() {
        order_chirho.push(node_chirho.clone());
        for edge_chirho in &dag_chirho.edges_chirho {
            if edge_chirho.from_node_chirho == node_chirho {
                if let Some(degree_chirho) = indegree_chirho.get_mut(&edge_chirho.to_node_chirho) {
                    *degree_chirho -= 1;
                    if *degree_chirho == 0 {
                        queue_chirho.push_back(edge_chirho.to_node_chirho.clone());
                    }
                }
            }
        }
    }
    if order_chirho.len() != dag_chirho.nodes_chirho.len() {
        return Err(anyhow!("DAG has a cycle or dangling edge"));
    }
    Ok(order_chirho)
}

/// Pure topology check (NO I/O): the DAG must be a single connected chain with no fan-in/fan-out.
/// Shared by the sync + async executors so both reject identically; only node-loading differs.
fn validate_linear_topology_chirho(
    dag_chirho: &DagChirho,
    order_chirho: &[HashChirho],
) -> Result<()> {
    if dag_chirho.edges_chirho.len() != order_chirho.len().saturating_sub(1) {
        return Err(anyhow!(
            "run_linear_dag_chirho supports only a linear chain: {} nodes need {} edges, found {}",
            order_chirho.len(),
            order_chirho.len().saturating_sub(1),
            dag_chirho.edges_chirho.len()
        ));
    }
    for (i_chirho, node_hash_chirho) in order_chirho.iter().enumerate() {
        let out_chirho = dag_chirho
            .edges_chirho
            .iter()
            .filter(|e| &e.from_node_chirho == node_hash_chirho)
            .count();
        let in_chirho = dag_chirho
            .edges_chirho
            .iter()
            .filter(|e| &e.to_node_chirho == node_hash_chirho)
            .count();
        if out_chirho > 1 || in_chirho > 1 {
            return Err(anyhow!(
                "run_linear_dag_chirho: node {} has fan-in/fan-out; multi-port DAGs are a later brick",
                node_hash_chirho.0
            ));
        }
        if i_chirho + 1 < order_chirho.len()
            && !dag_chirho.edges_chirho.iter().any(|e| {
                &e.from_node_chirho == node_hash_chirho
                    && e.to_node_chirho == order_chirho[i_chirho + 1]
            })
        {
            return Err(anyhow!(
                "run_linear_dag_chirho: nodes are not one connected chain"
            ));
        }
    }
    Ok(())
}

/// Pure per-node port-shape check (exactly one input + one output). Shared by both executors.
fn check_node_ports_chirho(node_chirho: &NodeDefChirho) -> Result<()> {
    if node_chirho.inputs_chirho.len() != 1 || node_chirho.outputs_chirho.len() != 1 {
        return Err(anyhow!(
            "run_linear_dag_chirho: node {} must have exactly 1 input + 1 output port (got {} in, {} out)",
            node_chirho.name_chirho,
            node_chirho.inputs_chirho.len(),
            node_chirho.outputs_chirho.len()
        ));
    }
    Ok(())
}

/// Reject any DAG that is not a single linear chain of single-input/single-output nodes, so the
/// linear executor never *silently* mis-runs a fan-in / multi-port DAG (those are a later brick).
fn validate_linear_chain_chirho<C: ContentStoreChirho>(
    dag_chirho: &DagChirho,
    order_chirho: &[HashChirho],
    content_store_chirho: &C,
) -> Result<()> {
    validate_linear_topology_chirho(dag_chirho, order_chirho)?;
    for node_hash_chirho in order_chirho {
        check_node_ports_chirho(&load_node_chirho(content_store_chirho, node_hash_chirho)?)?;
    }
    Ok(())
}

/// Run a **linear** pure-node DAG over the ports. `external_input_chirho` feeds the first node;
/// each node's single output feeds the next (M35.3 limitation — single input/output, no port
/// wiring yet). Every input/output is stored in the content store; one `RuntimeNodeRunChirho`
/// provenance record is appended per node. Generic over the three ports so the same code runs over
/// any backend (memory, fs, browser …).
pub fn run_linear_dag_chirho<C, A, R>(
    dag_chirho: &DagChirho,
    external_input_chirho: &[u8],
    content_store_chirho: &C,
    audit_log_chirho: &A,
    node_runner_chirho: &R,
    writer_chirho: &str,
) -> Result<DagRunResultChirho>
where
    C: ContentStoreChirho,
    A: AuditLogChirho,
    R: NodeRunnerChirho,
{
    let order_chirho = topo_order_chirho(dag_chirho)?;
    if order_chirho.is_empty() {
        return Err(anyhow!("cannot run an empty DAG"));
    }
    validate_linear_chain_chirho(dag_chirho, &order_chirho, content_store_chirho)?;
    let mut current_chirho = external_input_chirho.to_vec();
    let mut last_audit_chirho: Option<HashChirho> = None;
    for node_hash_chirho in &order_chirho {
        let node_chirho = load_node_chirho(content_store_chirho, node_hash_chirho)?;
        let input_hash_chirho = content_store_chirho.put_chirho(&current_chirho)?;
        let output_chirho = node_runner_chirho.run_node_chirho(&node_chirho, &current_chirho)?;
        let output_hash_chirho = content_store_chirho.put_chirho(&output_chirho)?;
        let provenance_chirho = RuntimeNodeRunChirho::new_chirho(
            node_hash_chirho.clone(),
            input_hash_chirho,
            output_hash_chirho,
        );
        let payload_chirho = serde_json::to_vec(&provenance_chirho)?;
        last_audit_chirho = Some(audit_log_chirho.append_chirho(writer_chirho, &payload_chirho)?);
        current_chirho = output_chirho;
    }
    Ok(DagRunResultChirho {
        output_hash_chirho: hash_chirho(&current_chirho),
        audit_head_chirho: last_audit_chirho.ok_or_else(|| anyhow!("empty DAG produced no run"))?,
    })
}

/// Async sibling of `load_node_chirho` (resolves a content-addressed node def over an async store).
async fn load_node_async_chirho<C: ContentStoreAsyncChirho>(
    store_chirho: &C,
    node_hash_chirho: &HashChirho,
) -> Result<NodeDefChirho> {
    let bytes_chirho = store_chirho
        .get_chirho(node_hash_chirho)
        .await?
        .ok_or_else(|| anyhow!("node {} not in content store", node_hash_chirho.0))?;
    Ok(serde_json::from_slice(&bytes_chirho)?)
}

/// Async sibling of `validate_linear_chain_chirho` — same shared pure checks, async node loads.
async fn validate_linear_chain_async_chirho<C: ContentStoreAsyncChirho>(
    dag_chirho: &DagChirho,
    order_chirho: &[HashChirho],
    content_store_chirho: &C,
) -> Result<()> {
    validate_linear_topology_chirho(dag_chirho, order_chirho)?;
    for node_hash_chirho in order_chirho {
        check_node_ports_chirho(
            &load_node_async_chirho(content_store_chirho, node_hash_chirho).await?,
        )?;
    }
    Ok(())
}

/// ADDITIVE async sibling of [`run_linear_dag_chirho`] over the **async** ports — the M35.6a spine
/// for browser backends whose I/O is asynchronous (IndexedDB). Same algorithm, same provenance, same
/// content addresses; only the storage calls are `.await`ed. `NodeRunnerChirho` stays synchronous
/// (node execution is CPU/wasm, not I/O). Proven byte-identical to the sync executor by running both
/// over a `SyncAsAsyncChirho`-bridged memory backend (see tests).
pub async fn run_linear_dag_async_chirho<C, A, R>(
    dag_chirho: &DagChirho,
    external_input_chirho: &[u8],
    content_store_chirho: &C,
    audit_log_chirho: &A,
    node_runner_chirho: &R,
    writer_chirho: &str,
) -> Result<DagRunResultChirho>
where
    C: ContentStoreAsyncChirho,
    A: AuditLogAsyncChirho,
    R: NodeRunnerChirho,
{
    let order_chirho = topo_order_chirho(dag_chirho)?;
    if order_chirho.is_empty() {
        return Err(anyhow!("cannot run an empty DAG"));
    }
    validate_linear_chain_async_chirho(dag_chirho, &order_chirho, content_store_chirho).await?;
    let mut current_chirho = external_input_chirho.to_vec();
    let mut last_audit_chirho: Option<HashChirho> = None;
    for node_hash_chirho in &order_chirho {
        let node_chirho = load_node_async_chirho(content_store_chirho, node_hash_chirho).await?;
        let input_hash_chirho = content_store_chirho.put_chirho(&current_chirho).await?;
        let output_chirho = node_runner_chirho.run_node_chirho(&node_chirho, &current_chirho)?;
        let output_hash_chirho = content_store_chirho.put_chirho(&output_chirho).await?;
        let provenance_chirho = RuntimeNodeRunChirho::new_chirho(
            node_hash_chirho.clone(),
            input_hash_chirho,
            output_hash_chirho,
        );
        let payload_chirho = serde_json::to_vec(&provenance_chirho)?;
        last_audit_chirho = Some(
            audit_log_chirho
                .append_chirho(writer_chirho, &payload_chirho)
                .await?,
        );
        current_chirho = output_chirho;
    }
    Ok(DagRunResultChirho {
        output_hash_chirho: hash_chirho(&current_chirho),
        audit_head_chirho: last_audit_chirho.ok_or_else(|| anyhow!("empty DAG produced no run"))?,
    })
}

/// Effect kind -> its blessed implementation (args bytes -> result bytes).
pub type EffectFnChirho = Box<dyn Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync>;

/// A **durable** record-replay effect performer — cairn's "effects can't be un-sent" safety made
/// concrete, grounded in the content + audit ports (NOT a volatile map, so it survives a crash).
/// The first perform of an idempotency key runs the registered effect, stores the result in the
/// content store, and appends an `EffectRecordChirho` to the audit log. Any later perform of the
/// SAME key — even from a *fresh* performer after a restart — finds that record by walking the log,
/// loads the recorded result from the content store, and REPLAYS it WITHOUT re-running the effect.
/// So a re-run is idempotent + resumable: the contract cairn uses instead of cross-plane transactions.
///
/// Durability rests on the stores, not on this struct's memory: the only in-memory state is the
/// effect *registry* (re-registered on startup). Walking the per-writer chain is O(history); a
/// dedicated idempotency-key index is a later optimization, not a correctness need.
pub struct RecordReplayPerformerChirho<C: ContentStoreChirho, A: AuditLogChirho> {
    content_store_chirho: C,
    audit_log_chirho: A,
    writer_chirho: String,
    effects_chirho: HashMap<String, EffectFnChirho>,
}

impl<C: ContentStoreChirho, A: AuditLogChirho> RecordReplayPerformerChirho<C, A> {
    pub fn new_chirho(content_store_chirho: C, audit_log_chirho: A, writer_chirho: &str) -> Self {
        Self {
            content_store_chirho,
            audit_log_chirho,
            writer_chirho: writer_chirho.to_string(),
            effects_chirho: HashMap::new(),
        }
    }
    /// Register a blessed effect implementation under a kind.
    pub fn register_chirho(&mut self, kind_chirho: &str, effect_chirho: EffectFnChirho) {
        self.effects_chirho
            .insert(kind_chirho.to_string(), effect_chirho);
    }

    /// Walk the audit log (each writer's `prev_hash` chain from its head) for a prior effect record
    /// under `idempotency_key_chirho`. This is what makes replay survive a crash: truth lives in the
    /// durable log, not in process memory.
    fn find_prior_effect_chirho(
        &self,
        idempotency_key_chirho: &str,
    ) -> Result<Option<EffectRecordChirho>> {
        for head_chirho in self.audit_log_chirho.heads_chirho()? {
            let mut cursor_chirho = Some(head_chirho);
            while let Some(hash_value_chirho) = cursor_chirho {
                let record_chirho = match self.audit_log_chirho.get_chirho(&hash_value_chirho)? {
                    Some(r) => r,
                    None => break,
                };
                if let Ok(effect_chirho) =
                    serde_json::from_slice::<EffectRecordChirho>(&record_chirho.payload_chirho)
                {
                    if effect_chirho.schema_chirho == EFFECT_RECORD_SCHEMA_CHIRHO
                        && effect_chirho.idempotency_key_chirho == idempotency_key_chirho
                    {
                        return Ok(Some(effect_chirho));
                    }
                }
                cursor_chirho = record_chirho.prev_hash_chirho;
            }
        }
        Ok(None)
    }
}

impl<C: ContentStoreChirho, A: AuditLogChirho> EffectPerformerChirho
    for RecordReplayPerformerChirho<C, A>
{
    fn perform_chirho(
        &self,
        idempotency_key_chirho: &str,
        kind_chirho: &str,
        args_chirho: &[u8],
    ) -> Result<EffectOutcomeChirho> {
        // Replay path: this idempotency key is already recorded in the durable log -> return the
        // recorded result, do NOT re-run the effect.
        if let Some(record_chirho) = self.find_prior_effect_chirho(idempotency_key_chirho)? {
            let result_chirho = self
                .content_store_chirho
                .get_chirho(&record_chirho.result_hash_chirho)?
                .ok_or_else(|| {
                    anyhow!(
                        "effect result {} recorded but missing from content store",
                        record_chirho.result_hash_chirho.0
                    )
                })?;
            return Ok(EffectOutcomeChirho {
                result_chirho,
                record_chirho,
                replayed_chirho: true,
            });
        }
        // Perform path: run the effect once, persist its result, then record it to the audit log.
        let effect_chirho = self
            .effects_chirho
            .get(kind_chirho)
            .ok_or_else(|| anyhow!("no effect registered for kind {kind_chirho}"))?;
        let result_chirho = effect_chirho(args_chirho)?;
        let result_hash_chirho = self.content_store_chirho.put_chirho(&result_chirho)?;
        let record_chirho = EffectRecordChirho::new_chirho(
            kind_chirho,
            idempotency_key_chirho,
            hash_chirho(args_chirho),
            result_hash_chirho,
        );
        self.audit_log_chirho
            .append_chirho(&self.writer_chirho, &serde_json::to_vec(&record_chirho)?)?;
        Ok(EffectOutcomeChirho {
            result_chirho,
            record_chirho,
            replayed_chirho: false,
        })
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_core_chirho::model_chirho::{EdgeChirho, PortChirho};
    use cairn_core_chirho::ports_chirho::{
        record_hash_chirho, ContentReadChirho, StateAuditUnitOfWorkChirho, StateStoreChirho,
        SyncAsAsyncChirho,
    };
    use cairn_store_fs_chirho::{FsAuditLogChirho, FsContentStoreChirho};
    use cairn_store_memory_chirho::{
        MemoryAuditLogChirho, MemoryContentStoreChirho, MemoryStateStoreChirho,
    };
    use cairn_store_redb_chirho::RedbStateAuditStoreChirho;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    static TEST_DIR_COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);

    fn temp_root_chirho() -> std::path::PathBuf {
        let n_chirho = TEST_DIR_COUNTER_CHIRHO.fetch_add(1, Ordering::SeqCst);
        let dir_chirho =
            std::env::temp_dir().join(format!("cairn-rt-m353-{}-{}", std::process::id(), n_chirho));
        let _ = std::fs::remove_dir_all(&dir_chirho);
        std::fs::create_dir_all(&dir_chirho).unwrap();
        dir_chirho
    }

    /// A minimal single-input/single-output pure node definition (no real wasm — the fn runner
    /// dispatches on `name_chirho`).
    fn node_chirho(name_chirho: &str) -> NodeDefChirho {
        let schema_chirho = hash_chirho(b"bytes-schema-chirho");
        NodeDefChirho {
            name_chirho: name_chirho.to_string(),
            impl_wasm_chirho: hash_chirho(name_chirho.as_bytes()),
            entry_chirho: "run-chirho".to_string(),
            inputs_chirho: vec![PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: schema_chirho.clone(),
            }],
            outputs_chirho: vec![PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho,
            }],
            capabilities_chirho: vec![],
            effect_contract_set_chirho: None,
            fuel_limit_chirho: 1_000,
            max_output_bytes_chirho:
                cairn_core_chirho::model_chirho::DEFAULT_NODE_MAX_OUTPUT_BYTES_CHIRHO,
            max_memory_bytes_chirho:
                cairn_core_chirho::model_chirho::DEFAULT_NODE_MAX_MEMORY_BYTES_CHIRHO,
        }
    }

    /// A pure test node: input bytes -> output bytes (name-dispatched by the fn-table runner).
    type NodeFnChirho = fn(&[u8]) -> Vec<u8>;

    /// Fn-table NodeRunner: dispatches on the node's name. (Wasmtime is a server adapter; this is
    /// the portable test adapter.)
    struct FnNodeRunnerChirho {
        fns_chirho: HashMap<String, NodeFnChirho>,
    }
    impl NodeRunnerChirho for FnNodeRunnerChirho {
        fn run_node_chirho(
            &self,
            node_chirho: &NodeDefChirho,
            input_chirho: &[u8],
        ) -> Result<Vec<u8>> {
            let f_chirho = self
                .fns_chirho
                .get(&node_chirho.name_chirho)
                .ok_or_else(|| anyhow!("no fn registered for node {}", node_chirho.name_chirho))?;
            Ok(f_chirho(input_chirho))
        }
    }

    fn runner_chirho() -> FnNodeRunnerChirho {
        let mut fns_chirho: HashMap<String, NodeFnChirho> = HashMap::new();
        fns_chirho.insert("upcase-chirho".to_string(), |b| b.to_ascii_uppercase());
        fns_chirho.insert("reverse-chirho".to_string(), |b| {
            b.iter().rev().copied().collect()
        });
        FnNodeRunnerChirho { fns_chirho }
    }

    /// Build a 2-node linear DAG (upcase -> reverse), storing the node defs in `store` so the
    /// executor can resolve them by hash. Returns the DAG.
    fn build_dag_chirho<C: ContentStoreChirho>(store_chirho: &C) -> DagChirho {
        let upcase_chirho = node_chirho("upcase-chirho");
        let reverse_chirho = node_chirho("reverse-chirho");
        let upcase_hash_chirho = store_chirho
            .put_chirho(&serde_json::to_vec(&upcase_chirho).unwrap())
            .unwrap();
        let reverse_hash_chirho = store_chirho
            .put_chirho(&serde_json::to_vec(&reverse_chirho).unwrap())
            .unwrap();
        DagChirho {
            nodes_chirho: vec![upcase_hash_chirho.clone(), reverse_hash_chirho.clone()],
            edges_chirho: vec![EdgeChirho {
                from_node_chirho: upcase_hash_chirho,
                from_port_chirho: "out".to_string(),
                to_node_chirho: reverse_hash_chirho,
                to_port_chirho: "in".to_string(),
                privacy_chirho: None,
            }],
        }
    }

    #[test]
    fn same_dag_runs_identically_over_memory_and_fs_chirho() {
        let input_chirho = b"love Jesus";

        // memory backend
        let mem_cs_chirho = MemoryContentStoreChirho::new_chirho();
        let mem_al_chirho = MemoryAuditLogChirho::new_chirho();
        let mem_dag_chirho = build_dag_chirho(&mem_cs_chirho);
        let mem_result_chirho = run_linear_dag_chirho(
            &mem_dag_chirho,
            input_chirho,
            &mem_cs_chirho,
            &mem_al_chirho,
            &runner_chirho(),
            "runtime-chirho",
        )
        .unwrap();

        // fs backend
        let root_chirho = temp_root_chirho();
        let fs_cs_chirho = FsContentStoreChirho::new_chirho(&root_chirho);
        let fs_al_chirho = FsAuditLogChirho::new_chirho(&root_chirho);
        let fs_dag_chirho = build_dag_chirho(&fs_cs_chirho);
        let fs_result_chirho = run_linear_dag_chirho(
            &fs_dag_chirho,
            input_chirho,
            &fs_cs_chirho,
            &fs_al_chirho,
            &runner_chirho(),
            "runtime-chirho",
        )
        .unwrap();

        // THE PROOF: identical final output AND identical provenance across both backends.
        assert_eq!(
            mem_dag_chirho, fs_dag_chirho,
            "DAG (node hashes) differ across backends"
        );
        assert_eq!(
            mem_result_chirho.output_hash_chirho, fs_result_chirho.output_hash_chirho,
            "final output hash differs across backends"
        );
        assert_eq!(
            mem_result_chirho.audit_head_chirho, fs_result_chirho.audit_head_chirho,
            "audit head differs across backends"
        );

        // explicit provenance-PAYLOAD equality (GPT's refinement), not just heads:
        let mem_rec_chirho = mem_al_chirho
            .get_chirho(&mem_result_chirho.audit_head_chirho)
            .unwrap()
            .unwrap();
        let fs_rec_chirho = fs_al_chirho
            .get_chirho(&fs_result_chirho.audit_head_chirho)
            .unwrap()
            .unwrap();
        assert_eq!(
            hash_chirho(&mem_rec_chirho.payload_chirho),
            hash_chirho(&fs_rec_chirho.payload_chirho),
            "provenance payload hash differs across backends"
        );
        assert_eq!(
            record_hash_chirho(&mem_rec_chirho).unwrap(),
            record_hash_chirho(&fs_rec_chirho).unwrap()
        );

        // the payload is the typed, schema-tagged run record for the last (reverse) node:
        let prov_chirho: RuntimeNodeRunChirho =
            serde_json::from_slice(&fs_rec_chirho.payload_chirho).unwrap();
        assert_eq!(prov_chirho.schema_chirho, RUNTIME_NODE_RUN_SCHEMA_CHIRHO);
        assert_eq!(
            prov_chirho.output_hash_chirho,
            fs_result_chirho.output_hash_chirho
        );

        // sanity: upcase then reverse of "love Jesus" = "SUSEJ EVOL"
        assert_eq!(
            fs_cs_chirho
                .get_chirho(&fs_result_chirho.output_hash_chirho)
                .unwrap()
                .as_deref(),
            Some(&b"SUSEJ EVOL"[..])
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn rejects_fan_in_dag_chirho() {
        // Two nodes feeding a third (fan-in): the linear executor must REJECT this clearly,
        // not silently run only the first edge.
        let store_chirho = MemoryContentStoreChirho::new_chirho();
        let a_chirho = store_chirho
            .put_chirho(&serde_json::to_vec(&node_chirho("a-chirho")).unwrap())
            .unwrap();
        let b_chirho = store_chirho
            .put_chirho(&serde_json::to_vec(&node_chirho("b-chirho")).unwrap())
            .unwrap();
        let c_chirho = store_chirho
            .put_chirho(&serde_json::to_vec(&node_chirho("c-chirho")).unwrap())
            .unwrap();
        let dag_chirho = DagChirho {
            nodes_chirho: vec![a_chirho.clone(), b_chirho.clone(), c_chirho.clone()],
            edges_chirho: vec![
                EdgeChirho {
                    from_node_chirho: a_chirho,
                    from_port_chirho: "out".to_string(),
                    to_node_chirho: c_chirho.clone(),
                    to_port_chirho: "in".to_string(),
                    privacy_chirho: None,
                },
                EdgeChirho {
                    from_node_chirho: b_chirho,
                    from_port_chirho: "out".to_string(),
                    to_node_chirho: c_chirho,
                    to_port_chirho: "in".to_string(),
                    privacy_chirho: None,
                },
            ],
        };
        let result_chirho = run_linear_dag_chirho(
            &dag_chirho,
            b"x",
            &store_chirho,
            &MemoryAuditLogChirho::new_chirho(),
            &runner_chirho(),
            "w-chirho",
        );
        assert!(
            result_chirho.is_err(),
            "fan-in DAG must be rejected, not silently mis-run"
        );
    }

    // --- M35.5 effect-plane write-atomicity proofs: durable record-replay + idempotent state. ---
    // "Restart"/"crash" are modeled by DROPPING the performer (its in-memory effect registry is gone)
    // while the content + audit stores live on — truth lives in the durable log, not process memory.

    /// A performer whose one `incr-chirho` effect bumps an observable run-counter on each REAL run
    /// (so a test can prove replay does NOT re-run it) and returns `parse(args)+1` as ascii. Both
    /// ports are passed by reference (the blanket `&T` port impls), so several performers can share
    /// ONE durable store across a simulated restart.
    fn incr_performer_chirho<'a>(
        cs_chirho: &'a MemoryContentStoreChirho,
        al_chirho: &'a MemoryAuditLogChirho,
        runs_chirho: Arc<AtomicU64>,
    ) -> RecordReplayPerformerChirho<&'a MemoryContentStoreChirho, &'a MemoryAuditLogChirho> {
        let mut perf_chirho =
            RecordReplayPerformerChirho::new_chirho(cs_chirho, al_chirho, "effects-chirho");
        perf_chirho.register_chirho(
            "incr-chirho",
            Box::new(move |args_chirho: &[u8]| {
                runs_chirho.fetch_add(1, Ordering::SeqCst); // observable side effect: a real run
                let n_chirho = std::str::from_utf8(args_chirho)
                    .ok()
                    .and_then(|s_chirho| s_chirho.parse::<u64>().ok())
                    .unwrap_or(0);
                Ok((n_chirho + 1).to_string().into_bytes())
            }),
        );
        perf_chirho
    }

    /// An effect runs exactly once even across a process restart: a fresh performer over the SAME
    /// durable store finds the prior `EffectRecordChirho` in the log and REPLAYS the recorded result
    /// instead of re-running the effect; a different idempotency key performs anew.
    #[test]
    fn effect_replays_across_a_restart_chirho() {
        let cs_chirho = MemoryContentStoreChirho::new_chirho();
        let al_chirho = MemoryAuditLogChirho::new_chirho();
        let runs_chirho = Arc::new(AtomicU64::new(0));

        // process 1: first perform of "op-1" RUNS the effect
        {
            let perf_chirho = incr_performer_chirho(&cs_chirho, &al_chirho, runs_chirho.clone());
            let out_chirho = perf_chirho
                .perform_chirho("op-1", "incr-chirho", b"0")
                .unwrap();
            assert!(
                !out_chirho.replayed_chirho,
                "first perform must RUN the effect"
            );
            assert_eq!(out_chirho.result_chirho, b"1");
        } // performer dropped == restart boundary (its registry memory is gone)
        assert_eq!(runs_chirho.load(Ordering::SeqCst), 1);

        // process 2 (restart): same key REPLAYS from the durable log; the effect does NOT re-run
        {
            let perf_chirho = incr_performer_chirho(&cs_chirho, &al_chirho, runs_chirho.clone());
            let out_chirho = perf_chirho
                .perform_chirho("op-1", "incr-chirho", b"0")
                .unwrap();
            assert!(
                out_chirho.replayed_chirho,
                "same key after restart must REPLAY"
            );
            assert_eq!(
                out_chirho.result_chirho, b"1",
                "replay returns the recorded result"
            );
        }
        assert_eq!(
            runs_chirho.load(Ordering::SeqCst),
            1,
            "replay must NOT re-run the effect"
        );

        // a different idempotency key performs fresh
        {
            let perf_chirho = incr_performer_chirho(&cs_chirho, &al_chirho, runs_chirho.clone());
            let out_chirho = perf_chirho
                .perform_chirho("op-2", "incr-chirho", b"5")
                .unwrap();
            assert!(
                !out_chirho.replayed_chirho,
                "a new key must perform, not replay"
            );
            assert_eq!(out_chirho.result_chirho, b"6");
        }
        assert_eq!(runs_chirho.load(Ordering::SeqCst), 2);
    }

    /// Crash AFTER the effect is performed+recorded but BEFORE the state mutation is applied. On
    /// resume the whole op re-runs: the effect REPLAYS (not re-sent) and `apply_once` applies the
    /// state for the first time — exactly once, no lost update, no double-send.
    #[test]
    fn crash_after_effect_before_state_reapplies_state_once_chirho() {
        let cs_chirho = MemoryContentStoreChirho::new_chirho();
        let al_chirho = MemoryAuditLogChirho::new_chirho();
        let state_chirho = MemoryStateStoreChirho::new_chirho();
        let runs_chirho = Arc::new(AtomicU64::new(0));

        // process 1: perform the effect, then CRASH before applying state
        {
            let perf_chirho = incr_performer_chirho(&cs_chirho, &al_chirho, runs_chirho.clone());
            let out_chirho = perf_chirho
                .perform_chirho("op-1", "incr-chirho", b"0")
                .unwrap();
            assert!(!out_chirho.replayed_chirho);
            // <-- crash here: state apply for "op-1" never happened
        }
        assert_eq!(runs_chirho.load(Ordering::SeqCst), 1);
        assert!(!state_chirho.is_applied_chirho("op-1").unwrap());
        assert!(state_chirho.get_state_chirho("counter").unwrap().is_none());

        // process 2 (resume): re-run the op end-to-end
        {
            let perf_chirho = incr_performer_chirho(&cs_chirho, &al_chirho, runs_chirho.clone());
            let out_chirho = perf_chirho
                .perform_chirho("op-1", "incr-chirho", b"0")
                .unwrap();
            assert!(
                out_chirho.replayed_chirho,
                "effect must replay, not re-send"
            );
            let applied_chirho = state_chirho
                .apply_once_chirho("op-1", "counter", &out_chirho.result_chirho)
                .unwrap();
            assert!(applied_chirho, "state applies for the first time on resume");
        }
        assert_eq!(
            runs_chirho.load(Ordering::SeqCst),
            1,
            "effect was NOT re-sent"
        );
        assert_eq!(
            state_chirho.get_state_chirho("counter").unwrap(),
            Some(b"1".to_vec())
        );

        // process 3: a redundant resume doubles nothing
        {
            let perf_chirho = incr_performer_chirho(&cs_chirho, &al_chirho, runs_chirho.clone());
            let out_chirho = perf_chirho
                .perform_chirho("op-1", "incr-chirho", b"0")
                .unwrap();
            let applied_chirho = state_chirho
                .apply_once_chirho("op-1", "counter", &out_chirho.result_chirho)
                .unwrap();
            assert!(out_chirho.replayed_chirho);
            assert!(!applied_chirho, "state must not re-apply");
        }
        assert_eq!(runs_chirho.load(Ordering::SeqCst), 1);
        assert_eq!(
            state_chirho.get_state_chirho("counter").unwrap(),
            Some(b"1".to_vec())
        );
    }

    /// Crash AFTER the state mutation is applied but BEFORE the higher-level run provenance is
    /// recorded. On resume the op re-runs: the effect REPLAYS and `apply_once` is a no-op (already
    /// applied) — the counter does NOT double-increment.
    #[test]
    fn crash_after_state_before_provenance_does_not_reapply_chirho() {
        let cs_chirho = MemoryContentStoreChirho::new_chirho();
        let al_chirho = MemoryAuditLogChirho::new_chirho();
        let state_chirho = MemoryStateStoreChirho::new_chirho();
        let runs_chirho = Arc::new(AtomicU64::new(0));

        // process 1: effect + state both done, then CRASH before recording run provenance
        {
            let perf_chirho = incr_performer_chirho(&cs_chirho, &al_chirho, runs_chirho.clone());
            let out_chirho = perf_chirho
                .perform_chirho("op-1", "incr-chirho", b"0")
                .unwrap();
            assert!(!out_chirho.replayed_chirho);
            assert!(state_chirho
                .apply_once_chirho("op-1", "counter", &out_chirho.result_chirho)
                .unwrap());
            // <-- crash before the run-provenance record is appended
        }
        assert_eq!(runs_chirho.load(Ordering::SeqCst), 1);
        assert_eq!(
            state_chirho.get_state_chirho("counter").unwrap(),
            Some(b"1".to_vec())
        );

        // process 2 (resume): re-running must double NOTHING
        {
            let perf_chirho = incr_performer_chirho(&cs_chirho, &al_chirho, runs_chirho.clone());
            let out_chirho = perf_chirho
                .perform_chirho("op-1", "incr-chirho", b"0")
                .unwrap();
            let applied_chirho = state_chirho
                .apply_once_chirho("op-1", "counter", &out_chirho.result_chirho)
                .unwrap();
            assert!(out_chirho.replayed_chirho, "effect replays on resume");
            assert!(
                !applied_chirho,
                "state already applied -> apply_once is a no-op"
            );
        }
        assert_eq!(runs_chirho.load(Ordering::SeqCst), 1, "effect NOT re-sent");
        assert_eq!(
            state_chirho.get_state_chirho("counter").unwrap(),
            Some(b"1".to_vec()),
            "counter must NOT double-increment"
        );
    }

    /// The M35.7 durability proof: the record-replay effect performer survives a REAL backend reopen,
    /// not only a shared in-memory store. Effect output is persisted by the fs content adapter; the
    /// effect record, mutable state, and state-audit commit live in redb. A fresh performer after all
    /// handles are dropped finds the prior effect record, loads the fs content result, and the redb
    /// unit-of-work refuses to duplicate the state/audit commit for the same mutation id.
    #[test]
    fn effect_replays_across_real_fs_redb_reopen_with_atomic_state_audit_chirho() {
        let root_chirho = temp_root_chirho();
        let redb_path_chirho = root_chirho.join("state-audit-chirho.redb");
        let runs_chirho = Arc::new(AtomicU64::new(0));
        let first_state_audit_chirho: HashChirho;

        {
            let fs_chirho = FsContentStoreChirho::new_chirho(&root_chirho);
            let redb_chirho = RedbStateAuditStoreChirho::open_chirho(&redb_path_chirho).unwrap();
            let mut perf_chirho =
                RecordReplayPerformerChirho::new_chirho(&fs_chirho, &redb_chirho, "effects-chirho");
            let runs_for_effect_chirho = runs_chirho.clone();
            perf_chirho.register_chirho(
                "incr-chirho",
                Box::new(move |args_chirho: &[u8]| {
                    runs_for_effect_chirho.fetch_add(1, Ordering::SeqCst);
                    let n_chirho = std::str::from_utf8(args_chirho)
                        .ok()
                        .and_then(|s_chirho| s_chirho.parse::<u64>().ok())
                        .unwrap_or(0);
                    Ok((n_chirho + 1).to_string().into_bytes())
                }),
            );

            let out_chirho = perf_chirho
                .perform_chirho("op-1", "incr-chirho", b"0")
                .unwrap();
            assert!(!out_chirho.replayed_chirho);
            assert_eq!(out_chirho.result_chirho, b"1");
            let commit_chirho = redb_chirho
                .commit_state_and_audit_chirho(
                    "op-1/state",
                    "counter",
                    &out_chirho.result_chirho,
                    "state-chirho",
                    b"counter=1",
                )
                .unwrap();
            assert!(commit_chirho.state_applied_chirho);
            first_state_audit_chirho = commit_chirho.audit_head_chirho;
            assert_eq!(
                redb_chirho.get_state_chirho("counter").unwrap(),
                Some(b"1".to_vec())
            );
        } // drop every handle: this is the real reopen / restart boundary

        assert_eq!(runs_chirho.load(Ordering::SeqCst), 1);

        {
            let fs_chirho = FsContentStoreChirho::new_chirho(&root_chirho);
            let redb_chirho = RedbStateAuditStoreChirho::open_chirho(&redb_path_chirho).unwrap();
            assert_eq!(
                redb_chirho.get_state_chirho("counter").unwrap(),
                Some(b"1".to_vec()),
                "redb state must survive reopen"
            );
            let mut perf_chirho =
                RecordReplayPerformerChirho::new_chirho(&fs_chirho, &redb_chirho, "effects-chirho");
            let runs_for_effect_chirho = runs_chirho.clone();
            perf_chirho.register_chirho(
                "incr-chirho",
                Box::new(move |args_chirho: &[u8]| {
                    runs_for_effect_chirho.fetch_add(1, Ordering::SeqCst);
                    let n_chirho = std::str::from_utf8(args_chirho)
                        .ok()
                        .and_then(|s_chirho| s_chirho.parse::<u64>().ok())
                        .unwrap_or(0);
                    Ok((n_chirho + 1).to_string().into_bytes())
                }),
            );

            let replay_chirho = perf_chirho
                .perform_chirho("op-1", "incr-chirho", b"0")
                .unwrap();
            assert!(
                replay_chirho.replayed_chirho,
                "fresh performer must replay from redb audit + fs content"
            );
            assert_eq!(replay_chirho.result_chirho, b"1");
            assert_eq!(
                runs_chirho.load(Ordering::SeqCst),
                1,
                "reopen replay must not re-run the effect"
            );

            let second_commit_chirho = redb_chirho
                .commit_state_and_audit_chirho(
                    "op-1/state",
                    "counter",
                    &replay_chirho.result_chirho,
                    "state-chirho",
                    b"counter=1",
                )
                .unwrap();
            assert!(
                !second_commit_chirho.state_applied_chirho,
                "same mutation id must not duplicate state/audit"
            );
            assert_eq!(
                second_commit_chirho.audit_head_chirho, first_state_audit_chirho,
                "duplicate unit-of-work returns the original audit commit"
            );
            assert_eq!(
                redb_chirho.get_state_chirho("counter").unwrap(),
                Some(b"1".to_vec())
            );
        }

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    // --- M35.6a: async spine — the async executor is byte-identical to the sync one. ----------

    /// A tiny dependency-free `block_on` for the parity test: the bridged futures are always Ready,
    /// so one poll completes them. `Waker::noop()` is stable since Rust 1.85 (toolchain is 1.93).
    fn block_on_chirho<F: core::future::Future>(future_chirho: F) -> F::Output {
        use core::task::{Context, Poll, Waker};
        let mut pinned_chirho = Box::pin(future_chirho);
        let mut cx_chirho = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(out_chirho) = pinned_chirho.as_mut().poll(&mut cx_chirho) {
                return out_chirho;
            }
        }
    }

    /// THE M35.6a PROOF: the same pure DAG run through the ASYNC executor over a `SyncAsAsyncChirho`-
    /// bridged memory backend yields the IDENTICAL final output hash AND audit-record payload hash as
    /// the SYNC executor (head equality checked as an extra, not the only proof). No browser, no async
    /// runtime, no added dependency.
    #[test]
    fn async_executor_matches_sync_over_bridged_memory_chirho() {
        let input_chirho = b"love Jesus";

        // sync path (the existing executor)
        let sync_cs_chirho = MemoryContentStoreChirho::new_chirho();
        let sync_al_chirho = MemoryAuditLogChirho::new_chirho();
        let sync_dag_chirho = build_dag_chirho(&sync_cs_chirho);
        let sync_result_chirho = run_linear_dag_chirho(
            &sync_dag_chirho,
            input_chirho,
            &sync_cs_chirho,
            &sync_al_chirho,
            &runner_chirho(),
            "runtime-chirho",
        )
        .unwrap();

        // async path over the SAME logical backend, bridged sync -> async
        let async_cs_chirho = SyncAsAsyncChirho(MemoryContentStoreChirho::new_chirho());
        let async_al_chirho = SyncAsAsyncChirho(MemoryAuditLogChirho::new_chirho());
        let async_dag_chirho = build_dag_chirho(&async_cs_chirho.0);
        let async_result_chirho = block_on_chirho(run_linear_dag_async_chirho(
            &async_dag_chirho,
            input_chirho,
            &async_cs_chirho,
            &async_al_chirho,
            &runner_chirho(),
            "runtime-chirho",
        ))
        .unwrap();

        // THE PROOF: identical node hashes, identical final output hash, identical audit payload hash.
        assert_eq!(
            sync_dag_chirho, async_dag_chirho,
            "DAG (node hashes) differ sync vs async"
        );
        assert_eq!(
            sync_result_chirho.output_hash_chirho, async_result_chirho.output_hash_chirho,
            "final output hash differs sync vs async"
        );
        let sync_rec_chirho = sync_al_chirho
            .get_chirho(&sync_result_chirho.audit_head_chirho)
            .unwrap()
            .unwrap();
        let async_rec_chirho = async_al_chirho
            .0
            .get_chirho(&async_result_chirho.audit_head_chirho)
            .unwrap()
            .unwrap();
        assert_eq!(
            hash_chirho(&sync_rec_chirho.payload_chirho),
            hash_chirho(&async_rec_chirho.payload_chirho),
            "audit-record payload hash differs sync vs async"
        );
        // extra (not the only proof): the audit heads coincide too.
        assert_eq!(
            sync_result_chirho.audit_head_chirho, async_result_chirho.audit_head_chirho,
            "audit head differs sync vs async (extra check)"
        );
        // sanity: upcase then reverse of "love Jesus" = "SUSEJ EVOL"
        assert_eq!(
            async_cs_chirho
                .0
                .get_chirho(&async_result_chirho.output_hash_chirho)
                .unwrap()
                .as_deref(),
            Some(&b"SUSEJ EVOL"[..])
        );
    }
}
