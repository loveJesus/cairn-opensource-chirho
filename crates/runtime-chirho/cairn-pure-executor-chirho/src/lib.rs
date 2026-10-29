// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! B2.2.1 — run the PURE subset of a DAG on a read-only replica: capability-free WASM against a
//! verified content store, failing closed (by node name) on effect and native nodes, with no root
//! authority, no head mutation, and no effects.
//!
//! A replica may *recompute* what pure code determines from verified inputs; it may never
//! *originate* an effect. So `run_pure_dag_chirho` classifies every node BEFORE running any of
//! them: an effect node (`capabilities != []`) or a Tier-2 native node returns a typed refusal and
//! nothing runs. Every content read (node def, WASM impl) is re-hashed on read (M142), so the crate
//! is correct on ANY `ContentReadChirho`, not only a verifying adapter. It depends on nothing that
//! can write a head, append an effect, or sign — see `p3_replication_guard_tests_chirho`.
//!
//! Scope (B2.2.1): single-input chains (one source, one sink, each node ≤1 incoming edge) of pure
//! WASM nodes. Multi-input / builtin-phi execution and the disposable per-site pure cache are named
//! follow-ons (design: `spec-chirho/workflows-chirho/distributed-ha-chirho/b2-2-executor-extraction-design-chirho.md`).

use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::cas_chirho::hash_chirho;
use cairn_core_chirho::model_chirho::{
    DagChirho, HashChirho, NodeDefChirho, BUILTIN_PHI_IMPL_CHIRHO, NATIVE_NODE_IMPL_PREFIX_CHIRHO,
};
use cairn_core_chirho::ports_chirho::{verify_content_address_chirho, ContentReadChirho};
use cairn_wasmtime_runner_chirho::runner_chirho::run_node_bytes_chirho;
use std::collections::{BTreeMap, HashMap};

/// How a node is treated by a replica's pure executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKindChirho {
    /// Capability-free real WASM — runnable here.
    PureWasmChirho,
    /// The builtin-phi merge node: pure but multi-input; NOT executed in the B2.2.1 single-input
    /// scope (a named follow-on), refused as an unsupported shape rather than an authority breach.
    BuiltinPhiChirho,
    /// A node with capabilities — an EFFECT node. A replica holds no authority to mint effects;
    /// FAIL CLOSED.
    EffectChirho,
    /// A Tier-2 native (native-program) node — needs host process authority a replica must not
    /// exercise; FAIL CLOSED.
    NativeChirho,
}

/// Classify a node from its definition alone — pure string/shape checks, no store access, no root
/// authority. Native is checked FIRST (a native node's capability set is irrelevant to the fact
/// that it needs host authority).
pub fn classify_node_chirho(def_chirho: &NodeDefChirho) -> NodeKindChirho {
    if def_chirho
        .impl_wasm_chirho
        .0
        .starts_with(NATIVE_NODE_IMPL_PREFIX_CHIRHO)
    {
        return NodeKindChirho::NativeChirho;
    }
    if !def_chirho.capabilities_chirho.is_empty() {
        return NodeKindChirho::EffectChirho;
    }
    if def_chirho.impl_wasm_chirho.0 == BUILTIN_PHI_IMPL_CHIRHO {
        return NodeKindChirho::BuiltinPhiChirho;
    }
    NodeKindChirho::PureWasmChirho
}

/// One executed pure node's evidence: its def hash and the content address of its output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PureNodeRunChirho {
    pub node_chirho: HashChirho,
    pub output_hash_chirho: HashChirho,
}

/// The result of running a DAG on a replica. A refusal is an expected OUTCOME (the caller renders
/// the uniform client refusal and surfaces the named reason only in operator evidence — Q2), NOT an
/// error; an `Err` is a genuine fault (store failure, tampered bytes, unsupported shape, WASM trap).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PureDagOutcomeChirho {
    /// Every node was pure; the sink's output is the payload.
    PayloadChirho {
        bytes_chirho: Vec<u8>,
        output_hash_chirho: HashChirho,
        node_runs_chirho: Vec<PureNodeRunChirho>,
    },
    /// An effect node was present; nothing ran. `node_chirho` is the FIRST such node (dag order).
    RefusedEffectfulChirho { node_chirho: HashChirho },
    /// A native (Tier-2) node was present; nothing ran. `node_chirho` is the FIRST such node.
    RefusedNativeChirho { node_chirho: HashChirho },
}

/// Read bytes by content address and re-hash them before returning (M142) — so a tampered store
/// object faults here, before any node runs on it, on ANY adapter (verifying or not).
fn get_verified_chirho(
    store_chirho: &dyn ContentReadChirho,
    addr_chirho: &HashChirho,
    what_chirho: &str,
) -> Result<Vec<u8>> {
    let bytes_chirho = store_chirho
        .get_chirho(addr_chirho)
        .map_err(|error_chirho| anyhow!("read {what_chirho} {}: {error_chirho}", addr_chirho.0))?
        .ok_or_else(|| {
            anyhow!(
                "{what_chirho} {} is not in the replica store",
                addr_chirho.0
            )
        })?;
    verify_content_address_chirho(addr_chirho, &bytes_chirho)
        .map_err(|error_chirho| anyhow!("{what_chirho} failed verify-on-read: {error_chirho}"))?;
    Ok(bytes_chirho)
}

/// Load and verify every node definition in the DAG, in DAG order.
fn load_defs_chirho(
    store_chirho: &dyn ContentReadChirho,
    dag_chirho: &DagChirho,
) -> Result<Vec<(HashChirho, NodeDefChirho)>> {
    let mut defs_chirho = Vec::with_capacity(dag_chirho.nodes_chirho.len());
    for node_hash_chirho in &dag_chirho.nodes_chirho {
        let bytes_chirho = get_verified_chirho(store_chirho, node_hash_chirho, "node def")?;
        let def_chirho: NodeDefChirho =
            serde_json::from_slice(&bytes_chirho).map_err(|error_chirho| {
                anyhow!("parse node def {}: {error_chirho}", node_hash_chirho.0)
            })?;
        defs_chirho.push((node_hash_chirho.clone(), def_chirho));
    }
    Ok(defs_chirho)
}

/// Topologically order a single-input-chain DAG (Kahn). Errors on the shapes B2.2.1 does not run:
/// a node with more than one incoming edge (multi-input), a cycle, or an edge naming an unknown
/// node. Determinism: ties break by the node's position in `dag_chirho.nodes_chirho`.
fn topo_order_single_input_chirho(dag_chirho: &DagChirho) -> Result<Vec<HashChirho>> {
    let index_of_chirho: HashMap<&HashChirho, usize> = dag_chirho
        .nodes_chirho
        .iter()
        .enumerate()
        .map(|(i_chirho, hash_chirho)| (hash_chirho, i_chirho))
        .collect();
    let mut indegree_chirho: Vec<usize> = vec![0; dag_chirho.nodes_chirho.len()];
    let mut successors_chirho: Vec<Vec<usize>> = vec![Vec::new(); dag_chirho.nodes_chirho.len()];
    for edge_chirho in &dag_chirho.edges_chirho {
        let from_chirho = *index_of_chirho
            .get(&edge_chirho.from_node_chirho)
            .ok_or_else(|| anyhow!("edge from unknown node {}", edge_chirho.from_node_chirho.0))?;
        let to_chirho = *index_of_chirho
            .get(&edge_chirho.to_node_chirho)
            .ok_or_else(|| anyhow!("edge to unknown node {}", edge_chirho.to_node_chirho.0))?;
        indegree_chirho[to_chirho] += 1;
        if indegree_chirho[to_chirho] > 1 {
            bail!(
                "node {} has multiple incoming edges; multi-input execution is a B2.2.1 follow-on",
                dag_chirho.nodes_chirho[to_chirho].0
            );
        }
        successors_chirho[from_chirho].push(to_chirho);
    }
    // Seed the queue with sources (indegree 0), in DAG-declared order for determinism.
    let mut queue_chirho: Vec<usize> = (0..dag_chirho.nodes_chirho.len())
        .filter(|i_chirho| indegree_chirho[*i_chirho] == 0)
        .collect();
    let mut order_chirho: Vec<HashChirho> = Vec::with_capacity(dag_chirho.nodes_chirho.len());
    let mut head_chirho = 0;
    while head_chirho < queue_chirho.len() {
        let node_chirho = queue_chirho[head_chirho];
        head_chirho += 1;
        order_chirho.push(dag_chirho.nodes_chirho[node_chirho].clone());
        for &succ_chirho in &successors_chirho[node_chirho] {
            indegree_chirho[succ_chirho] -= 1;
            if indegree_chirho[succ_chirho] == 0 {
                queue_chirho.push(succ_chirho);
            }
        }
    }
    if order_chirho.len() != dag_chirho.nodes_chirho.len() {
        bail!("DAG has a cycle; the pure executor requires an acyclic single-input chain");
    }
    Ok(order_chirho)
}

/// Run the PURE subset of a DAG against a verified read-only store and return the sink's payload,
/// or a typed refusal if the DAG carries an effect or native node (in which case NOTHING runs).
///
/// `output_cap_chirho` bounds the sink payload's size (a hostile pure node cannot exhaust replica
/// memory through an unbounded output). Every content read is verify-on-read (M142).
pub fn run_pure_dag_chirho(
    store_chirho: &dyn ContentReadChirho,
    dag_chirho: &DagChirho,
    input_bytes_chirho: &[u8],
    output_cap_chirho: usize,
) -> Result<PureDagOutcomeChirho> {
    if dag_chirho.nodes_chirho.is_empty() {
        bail!("pure DAG has no nodes");
    }
    let defs_chirho = load_defs_chirho(store_chirho, dag_chirho)?;

    // Authority pre-pass: refuse the WHOLE DAG (nothing runs) if any node is effect or native.
    // First offender in DAG order, so the refusal is deterministic.
    let mut first_effect_chirho: Option<HashChirho> = None;
    let mut first_native_chirho: Option<HashChirho> = None;
    for (node_hash_chirho, def_chirho) in &defs_chirho {
        match classify_node_chirho(def_chirho) {
            NodeKindChirho::NativeChirho => {
                first_native_chirho.get_or_insert_with(|| node_hash_chirho.clone());
            }
            NodeKindChirho::EffectChirho => {
                first_effect_chirho.get_or_insert_with(|| node_hash_chirho.clone());
            }
            NodeKindChirho::PureWasmChirho | NodeKindChirho::BuiltinPhiChirho => {}
        }
    }
    // Native and effect are both authority refusals; report native first only when it is the
    // earliest offender, else effect. Simplest deterministic rule: whichever appears first in DAG
    // order. (They are separate variants so operator evidence can distinguish them.)
    match (&first_native_chirho, &first_effect_chirho) {
        (Some(native_chirho), Some(effect_chirho)) => {
            let native_idx_chirho = dag_chirho
                .nodes_chirho
                .iter()
                .position(|h| h == native_chirho);
            let effect_idx_chirho = dag_chirho
                .nodes_chirho
                .iter()
                .position(|h| h == effect_chirho);
            if native_idx_chirho <= effect_idx_chirho {
                return Ok(PureDagOutcomeChirho::RefusedNativeChirho {
                    node_chirho: native_chirho.clone(),
                });
            }
            return Ok(PureDagOutcomeChirho::RefusedEffectfulChirho {
                node_chirho: effect_chirho.clone(),
            });
        }
        (Some(native_chirho), None) => {
            return Ok(PureDagOutcomeChirho::RefusedNativeChirho {
                node_chirho: native_chirho.clone(),
            });
        }
        (None, Some(effect_chirho)) => {
            return Ok(PureDagOutcomeChirho::RefusedEffectfulChirho {
                node_chirho: effect_chirho.clone(),
            });
        }
        (None, None) => {}
    }

    // Every node is pure. Builtin-phi (multi-input) is out of the B2.2.1 single-input scope — an
    // unsupported SHAPE (Err), distinct from the authority refusals above.
    let defs_by_hash_chirho: HashMap<&HashChirho, &NodeDefChirho> =
        defs_chirho.iter().map(|(h, d)| (h, d)).collect();
    for (node_hash_chirho, def_chirho) in &defs_chirho {
        if classify_node_chirho(def_chirho) == NodeKindChirho::BuiltinPhiChirho {
            bail!(
                "node {} is a builtin-phi (multi-input) node; the B2.2.1 pure executor runs \
                 single-input chains only",
                node_hash_chirho.0
            );
        }
    }

    // A single source and single sink (one payload in, one payload out).
    let sources_chirho: Vec<&HashChirho> = dag_chirho
        .nodes_chirho
        .iter()
        .filter(|node_chirho| {
            !dag_chirho
                .edges_chirho
                .iter()
                .any(|edge_chirho| &edge_chirho.to_node_chirho == *node_chirho)
        })
        .collect();
    let sinks_chirho: Vec<&HashChirho> = dag_chirho
        .nodes_chirho
        .iter()
        .filter(|node_chirho| {
            !dag_chirho
                .edges_chirho
                .iter()
                .any(|edge_chirho| &edge_chirho.from_node_chirho == *node_chirho)
        })
        .collect();
    if sources_chirho.len() != 1 {
        bail!(
            "pure executor v1 requires exactly one source, found {}",
            sources_chirho.len()
        );
    }
    if sinks_chirho.len() != 1 {
        bail!(
            "pure executor v1 requires exactly one sink, found {}",
            sinks_chirho.len()
        );
    }
    let sink_chirho = sinks_chirho[0].clone();

    let order_chirho = topo_order_single_input_chirho(dag_chirho)?;

    // Execute the chain: the source consumes the request input; every other node consumes its one
    // predecessor's output (via the single incoming edge).
    let mut outputs_chirho: BTreeMap<HashChirho, Vec<u8>> = BTreeMap::new();
    let mut node_runs_chirho: Vec<PureNodeRunChirho> = Vec::with_capacity(order_chirho.len());
    for node_hash_chirho in &order_chirho {
        let incoming_chirho = dag_chirho
            .edges_chirho
            .iter()
            .find(|edge_chirho| &edge_chirho.to_node_chirho == node_hash_chirho);
        let input_for_node_chirho: Vec<u8> = match incoming_chirho {
            None => input_bytes_chirho.to_vec(),
            Some(edge_chirho) => outputs_chirho
                .get(&edge_chirho.from_node_chirho)
                .cloned()
                .ok_or_else(|| {
                    anyhow!(
                        "predecessor {} of {} produced no output (topo order bug)",
                        edge_chirho.from_node_chirho.0,
                        node_hash_chirho.0
                    )
                })?,
        };
        let def_chirho = *defs_by_hash_chirho
            .get(node_hash_chirho)
            .ok_or_else(|| anyhow!("node {} missing from defs", node_hash_chirho.0))?;
        let wasm_chirho =
            get_verified_chirho(store_chirho, &def_chirho.impl_wasm_chirho, "node wasm")?;
        let outcome_chirho = run_node_bytes_chirho(
            &wasm_chirho,
            &def_chirho.entry_chirho,
            &input_for_node_chirho,
            def_chirho.fuel_limit_chirho,
        )
        .map_err(|error_chirho| {
            anyhow!("run pure node {}: {error_chirho}", def_chirho.name_chirho)
        })?;
        if outcome_chirho.output_chirho.len() > output_cap_chirho {
            bail!(
                "pure node {} output {} bytes exceeds the cap {}",
                def_chirho.name_chirho,
                outcome_chirho.output_chirho.len(),
                output_cap_chirho
            );
        }
        let output_hash_chirho = hash_chirho(&outcome_chirho.output_chirho);
        node_runs_chirho.push(PureNodeRunChirho {
            node_chirho: node_hash_chirho.clone(),
            output_hash_chirho,
        });
        outputs_chirho.insert(node_hash_chirho.clone(), outcome_chirho.output_chirho);
    }

    let payload_chirho = outputs_chirho
        .remove(&sink_chirho)
        .ok_or_else(|| anyhow!("sink {} produced no output", sink_chirho.0))?;
    let output_hash_chirho = hash_chirho(&payload_chirho);
    Ok(PureDagOutcomeChirho::PayloadChirho {
        bytes_chirho: payload_chirho,
        output_hash_chirho,
        node_runs_chirho,
    })
}
