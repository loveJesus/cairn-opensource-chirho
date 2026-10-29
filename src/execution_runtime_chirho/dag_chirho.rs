// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The DAG executor — wire pure + effect nodes into a graph and run it through the cache.
//!
//! A request becomes: input bytes -> `source` -> ... -> `sink` -> payload. Each node runs via
//! the result cache (pure) or the effect log (effectful), so re-running an unchanged DAG is
//! all cache hits, and every node records its upstream run as a provenance parent.
//!
//! Scope (v1): one input edge per node (linear / chain shapes), single source and sink.
//! Topological order is Kahn's algorithm.

use crate::model_chirho::{DagChirho, EdgeChirho, HashChirho, NodeDefChirho, RequestContextChirho};
use crate::{
    cache_chirho, cas_chirho, dag_private_value_chirho, effect_chirho, native_worker_chirho,
    store_chirho,
};
use anyhow::{anyhow, bail, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::Path;

#[path = "dag_chirho/refusal_chirho.rs"]
pub mod refusal_chirho;

use refusal_chirho::{
    ensure_dag_execution_stage_chirho, wrap_dag_execution_stage_chirho,
    DagExecutionRefusalIdentityChirho,
};

pub const MAX_DAG_AGGREGATE_OUTPUT_BYTES_CHIRHO: usize = 50 * 1024 * 1024;

/// One node's execution within a DAG run.
#[derive(Debug, Clone)]
pub struct NodeRunChirho {
    pub node_name_chirho: String,
    pub node_chirho: HashChirho,
    pub run_chirho: HashChirho,
    pub cached_chirho: bool,
}

/// The outcome of a whole DAG run: per-node runs, plus the sink payload and its hash.
#[derive(Debug, Clone)]
pub struct DagRunReportChirho {
    pub node_runs_chirho: Vec<NodeRunChirho>,
    pub payload_hash_chirho: HashChirho,
    pub payload_chirho: Vec<u8>,
}

/// Workflow note: see `spec-chirho/workflows-chirho/private-dag-edge-values-chirho.md`
/// for the private input/private intermediate path that this value type carries.
#[derive(Debug, Clone)]
pub enum DagInputValueChirho {
    PublicBytesChirho(Vec<u8>),
    PrivateBytesChirho {
        subject_chirho: String,
        bytes_chirho: Vec<u8>,
    },
}

/// Execute a DAG of nodes on `input_bytes`, returning the sink payload and a per-node run
/// report. Node definitions and their WASM are loaded from the CAS by hash.
pub fn run_dag_chirho(
    root_chirho: &Path,
    dag_chirho: &DagChirho,
    input_bytes_chirho: &[u8],
) -> Result<DagRunReportChirho> {
    run_dag_with_context_chirho(root_chirho, dag_chirho, input_bytes_chirho, None)
}

/// An OPERATOR's own run of a DAG, with no request context: its private values join no account, for
/// that proven reason. Operator tools (the CLI's DAG commands, DAG-module runs) use this; a served request
/// never does, since it declares the app owner instead.
pub fn run_dag_as_operator_chirho(
    root_chirho: &Path,
    dag_chirho: &DagChirho,
    input_bytes_chirho: &[u8],
) -> Result<DagRunReportChirho> {
    let operator_chirho =
        crate::privacy_chirho::PrivateBlobAttributionChirho::not_account_scoped_chirho(
            crate::privacy_chirho::NotAccountScopedReasonChirho::OperatorRunChirho,
        );
    run_dag_with_context_and_effect_runtime_chirho(
        root_chirho,
        dag_chirho,
        input_bytes_chirho,
        None,
        effect_chirho::DagEffectRuntimePortsChirho {
            private_attribution_chirho: Some(&operator_chirho),
            ..effect_chirho::DagEffectRuntimePortsChirho::uncomposed_chirho()
        },
    )
}

pub fn run_dag_with_context_chirho(
    root_chirho: &Path,
    dag_chirho: &DagChirho,
    input_bytes_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<DagRunReportChirho> {
    run_dag_with_context_and_projection_read_chirho(
        root_chirho,
        dag_chirho,
        input_bytes_chirho,
        request_context_chirho,
        None,
    )
}

pub fn run_dag_with_context_and_projection_read_chirho(
    root_chirho: &Path,
    dag_chirho: &DagChirho,
    input_bytes_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    projection_read_chirho: Option<
        &dyn effect_chirho::projection_read_chirho::PublishedProjectionReadPortChirho,
    >,
) -> Result<DagRunReportChirho> {
    run_dag_with_context_and_effect_runtime_chirho(
        root_chirho,
        dag_chirho,
        input_bytes_chirho,
        request_context_chirho,
        effect_chirho::DagEffectRuntimePortsChirho {
            projection_read_chirho,
            postgres_reversible_chirho: None,
            llm_served_chirho: None,
            private_attribution_chirho: None,
        },
    )
}

pub fn run_dag_with_context_and_effect_runtime_chirho(
    root_chirho: &Path,
    dag_chirho: &DagChirho,
    input_bytes_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    runtime_ports_chirho: effect_chirho::DagEffectRuntimePortsChirho<'_>,
) -> Result<DagRunReportChirho> {
    run_dag_with_context_and_parents_chirho(
        root_chirho,
        dag_chirho,
        DagInputValueChirho::PublicBytesChirho(input_bytes_chirho.to_vec()),
        request_context_chirho,
        &[],
        None,
        runtime_ports_chirho,
    )
}

pub fn run_dag_with_context_and_private_input_chirho(
    root_chirho: &Path,
    dag_chirho: &DagChirho,
    subject_chirho: &str,
    input_bytes_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<DagRunReportChirho> {
    run_dag_with_context_and_private_input_and_projection_read_chirho(
        root_chirho,
        dag_chirho,
        subject_chirho,
        input_bytes_chirho,
        request_context_chirho,
        None,
    )
}

pub fn run_dag_with_context_and_private_input_and_projection_read_chirho(
    root_chirho: &Path,
    dag_chirho: &DagChirho,
    subject_chirho: &str,
    input_bytes_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    projection_read_chirho: Option<
        &dyn effect_chirho::projection_read_chirho::PublishedProjectionReadPortChirho,
    >,
) -> Result<DagRunReportChirho> {
    run_dag_with_context_and_private_input_and_effect_runtime_chirho(
        root_chirho,
        dag_chirho,
        subject_chirho,
        input_bytes_chirho,
        request_context_chirho,
        effect_chirho::DagEffectRuntimePortsChirho {
            projection_read_chirho,
            postgres_reversible_chirho: None,
            llm_served_chirho: None,
            private_attribution_chirho: None,
        },
    )
}

pub fn run_dag_with_context_and_private_input_and_effect_runtime_chirho(
    root_chirho: &Path,
    dag_chirho: &DagChirho,
    subject_chirho: &str,
    input_bytes_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    runtime_ports_chirho: effect_chirho::DagEffectRuntimePortsChirho<'_>,
) -> Result<DagRunReportChirho> {
    run_dag_with_context_and_parents_chirho(
        root_chirho,
        dag_chirho,
        DagInputValueChirho::PrivateBytesChirho {
            subject_chirho: subject_chirho.to_string(),
            bytes_chirho: input_bytes_chirho.to_vec(),
        },
        request_context_chirho,
        &[],
        None,
        runtime_ports_chirho,
    )
}

/// An ADMITTED run with a private input (checkpoint brick S5a, agy #25958 option 1). Its admission already stored the
/// request, before the run's pending record (`persist_request_before_admission_chirho`), so the run reuses that record
/// rather than storing the bytes a second time; see `reuse_admitted_private_request_chirho`.
/// Workflow: `spec-chirho/workflows-chirho/perf-chirho/execution-checkpoint-brick-design-chirho.md` (S5a).
pub(crate) fn run_dag_with_admitted_private_input_and_effect_runtime_chirho(
    root_chirho: &Path,
    dag_chirho: &DagChirho,
    subject_chirho: &str,
    input_bytes_chirho: &[u8],
    request_chirho: &HashChirho,
    request_context_chirho: Option<&RequestContextChirho>,
    runtime_ports_chirho: effect_chirho::DagEffectRuntimePortsChirho<'_>,
) -> Result<DagRunReportChirho> {
    run_dag_with_context_and_parents_chirho(
        root_chirho,
        dag_chirho,
        DagInputValueChirho::PrivateBytesChirho {
            subject_chirho: subject_chirho.to_string(),
            bytes_chirho: input_bytes_chirho.to_vec(),
        },
        request_context_chirho,
        &[],
        Some(request_chirho),
        runtime_ports_chirho,
    )
}

pub fn run_dag_with_parents_chirho(
    root_chirho: &Path,
    dag_chirho: &DagChirho,
    input_bytes_chirho: &[u8],
    source_parents_chirho: &[HashChirho],
) -> Result<DagRunReportChirho> {
    run_dag_with_context_and_parents_chirho(
        root_chirho,
        dag_chirho,
        DagInputValueChirho::PublicBytesChirho(input_bytes_chirho.to_vec()),
        None,
        source_parents_chirho,
        None,
        effect_chirho::DagEffectRuntimePortsChirho::uncomposed_chirho(),
    )
}

/// `admitted_request_chirho` is the admitted run's request coordinate (S5a), present only on the admitted road.
fn run_dag_with_context_and_parents_chirho(
    root_chirho: &Path,
    dag_chirho: &DagChirho,
    input_value_chirho: DagInputValueChirho,
    request_context_chirho: Option<&RequestContextChirho>,
    source_parents_chirho: &[HashChirho],
    admitted_request_chirho: Option<&HashChirho>,
    runtime_ports_chirho: effect_chirho::DagEffectRuntimePortsChirho<'_>,
) -> Result<DagRunReportChirho> {
    run_dag_with_context_and_parents_and_output_cap_chirho(
        root_chirho,
        dag_chirho,
        DagRunInputChirho {
            value_chirho: input_value_chirho,
            admitted_request_chirho,
        },
        request_context_chirho,
        source_parents_chirho,
        MAX_DAG_AGGREGATE_OUTPUT_BYTES_CHIRHO,
        runtime_ports_chirho,
    )
}

/// A run's input, and, for an ADMITTED private run, the coordinate its admission already stored it under (S5a).
struct DagRunInputChirho<'a> {
    value_chirho: DagInputValueChirho,
    admitted_request_chirho: Option<&'a HashChirho>,
}

struct DagExecutionProgressChirho {
    output_bytes_cap_chirho: usize,
    effect_completed_chirho: bool,
}

fn run_dag_with_context_and_parents_and_output_cap_chirho(
    root_chirho: &Path,
    dag_chirho: &DagChirho,
    input_chirho: DagRunInputChirho<'_>,
    request_context_chirho: Option<&RequestContextChirho>,
    source_parents_chirho: &[HashChirho],
    output_bytes_cap_chirho: usize,
    runtime_ports_chirho: effect_chirho::DagEffectRuntimePortsChirho<'_>,
) -> Result<DagRunReportChirho> {
    let mut progress_chirho = DagExecutionProgressChirho {
        output_bytes_cap_chirho,
        effect_completed_chirho: false,
    };
    run_dag_with_context_and_parents_and_output_cap_inner_chirho(
        root_chirho,
        dag_chirho,
        input_chirho,
        request_context_chirho,
        source_parents_chirho,
        runtime_ports_chirho,
        &mut progress_chirho,
    )
    .map_err(|error_chirho| {
        let identity_chirho = if progress_chirho.effect_completed_chirho {
            DagExecutionRefusalIdentityChirho::DagPostEffectUnclassifiedRefusedChirho
        } else {
            DagExecutionRefusalIdentityChirho::DagPreEffectRefusedChirho
        };
        ensure_dag_execution_stage_chirho(identity_chirho, error_chirho)
    })
}

fn run_dag_with_context_and_parents_and_output_cap_inner_chirho(
    root_chirho: &Path,
    dag_chirho: &DagChirho,
    input_chirho: DagRunInputChirho<'_>,
    request_context_chirho: Option<&RequestContextChirho>,
    source_parents_chirho: &[HashChirho],
    mut runtime_ports_chirho: effect_chirho::DagEffectRuntimePortsChirho<'_>,
    progress_chirho: &mut DagExecutionProgressChirho,
) -> Result<DagRunReportChirho> {
    let DagRunInputChirho {
        value_chirho: input_value_chirho,
        admitted_request_chirho,
    } = input_chirho;
    let input_bytes_for_preflight_chirho = match &input_value_chirho {
        DagInputValueChirho::PublicBytesChirho(bytes_chirho) => bytes_chirho.as_slice(),
        DagInputValueChirho::PrivateBytesChirho { bytes_chirho, .. } => bytes_chirho.as_slice(),
    };
    let mut defs_chirho: HashMap<HashChirho, NodeDefChirho> = HashMap::new();
    for node_hash_chirho in &dag_chirho.nodes_chirho {
        let def_chirho: NodeDefChirho =
            store_chirho::get_object_chirho(root_chirho, node_hash_chirho)?;
        defs_chirho.insert(node_hash_chirho.clone(), def_chirho);
    }

    validate_viewer_state_input_privacy_chirho(
        dag_chirho,
        &defs_chirho,
        &input_value_chirho,
        request_context_chirho,
    )?;

    let order_chirho = topo_order_chirho(dag_chirho)?;
    for node_hash_chirho in &order_chirho {
        let incoming_chirho = dag_chirho
            .edges_chirho
            .iter()
            .any(|edge_chirho| &edge_chirho.to_node_chirho == node_hash_chirho);
        if !incoming_chirho {
            let def_chirho = defs_chirho
                .get(node_hash_chirho)
                .ok_or_else(|| anyhow!("node {} missing from defs", node_hash_chirho.0))?;
            effect_chirho::preflight_effect_request_chirho(
                &def_chirho.capabilities_chirho,
                input_bytes_for_preflight_chirho,
            )?;
        }
    }
    let mut resolver_chirho = dag_private_value_chirho::PrivateDagValueResolverChirho::default();
    // Whose container each private value of this run joins: its request when it has one, otherwise the
    // attribution its caller declared in the runtime ports. Neither refuses at the first private store.
    let declared_attribution_chirho = runtime_ports_chirho.private_attribution_chirho;
    let attribution_source_chirho =
        dag_private_value_chirho::RunAttributionSourceChirho::new_chirho(
            request_context_chirho,
            declared_attribution_chirho,
        );
    let input_hash_chirho = match input_value_chirho {
        DagInputValueChirho::PublicBytesChirho(bytes_chirho) => {
            cas_chirho::add_chirho(root_chirho, &bytes_chirho)?
        }
        DagInputValueChirho::PrivateBytesChirho {
            subject_chirho,
            bytes_chirho,
        } => match admitted_request_chirho {
            Some(request_chirho) => {
                dag_private_value_chirho::reuse_admitted_private_request_chirho(
                    root_chirho,
                    &subject_chirho,
                    &bytes_chirho,
                    request_chirho,
                    &mut resolver_chirho,
                )?
            }
            // A private run input is the request user's own (app_session's request-user plane).
            None => dag_private_value_chirho::store_dag_value_with_policy_chirho(
                root_chirho,
                &bytes_chirho,
                &dag_private_value_chirho::ValueStoragePolicyChirho::PrivateBlobRefChirho {
                    subject_chirho,
                    owner_chirho:
                        dag_private_value_chirho::PrivateValueOwnerChirho::RequestActorChirho,
                },
                dag_private_value_chirho::PrivateDagValueContextChirho::default(),
                Some(&mut resolver_chirho),
                &attribution_source_chirho,
            )?,
        },
    };

    let mut outputs_chirho: HashMap<(HashChirho, String), HashChirho> = HashMap::new();
    let mut run_of_chirho: HashMap<HashChirho, HashChirho> = HashMap::new();
    let mut node_runs_chirho: Vec<NodeRunChirho> = Vec::new();
    let mut aggregate_output_bytes_chirho = 0usize;

    for (node_step_chirho, node_hash_chirho) in order_chirho.iter().enumerate() {
        let def_chirho = defs_chirho
            .get(node_hash_chirho)
            .ok_or_else(|| anyhow!("node {} missing from defs", node_hash_chirho.0))?;

        let incoming_chirho: Vec<&EdgeChirho> = dag_chirho
            .edges_chirho
            .iter()
            .filter(|e_chirho| &e_chirho.to_node_chirho == node_hash_chirho)
            .collect();
        let (input_hashes_chirho, parents_chirho) = if incoming_chirho.is_empty() {
            let port_name_chirho = def_chirho
                .inputs_chirho
                .first()
                .map(|port_chirho| port_chirho.name_chirho.clone())
                .unwrap_or_else(|| "in".to_string());
            let mut input_hashes_chirho = BTreeMap::new();
            input_hashes_chirho.insert(port_name_chirho, input_hash_chirho.clone());
            (input_hashes_chirho, source_parents_chirho.to_vec())
        } else {
            collect_edge_inputs_chirho(
                &incoming_chirho,
                &outputs_chirho,
                &run_of_chirho,
                def_chirho,
                root_chirho,
                request_context_chirho,
                &mut resolver_chirho,
            )?
        };
        let contains_skipped_chirho = input_hashes_chirho.values().try_fold(
            false,
            |seen_chirho, hash_chirho| -> Result<bool> {
                Ok(seen_chirho || cache_chirho::is_skipped_hash_chirho(root_chirho, hash_chirho)?)
            },
        )?;

        let output_port_chirho = node_output_port_chirho(def_chirho);
        let declared_output_storage_chirho = output_storage_policy_chirho(
            dag_chirho,
            node_hash_chirho,
            &output_port_chirho,
            request_context_chirho,
        )?;
        // A builtin phi passes its live input through by hash, so its privacy is the LIVE input's
        // and nothing else's: a skipped stone that came off a private branch never privatises a
        // public live value, and a private live value keeps its subject. Every other node
        // inherits from all of its inputs.
        // Part of `spec-chirho/workflows-chirho/private-dag-edge-values-chirho.md`.
        let inherited_private_subject_chirho = if def_chirho.is_builtin_phi_chirho() {
            let (_live_port_chirho, live_hash_chirho) =
                cache_chirho::phi_live_input_chirho(root_chirho, def_chirho, &input_hashes_chirho)?;
            resolver_chirho.domain_for_hash_chirho(live_hash_chirho)?
        } else {
            inherited_private_subject_chirho(&input_hashes_chirho, &resolver_chirho)?
        };
        let output_storage_chirho = propagated_output_storage_policy_chirho(
            declared_output_storage_chirho,
            inherited_private_subject_chirho,
            node_hash_chirho,
            &output_port_chirho,
        )?;

        // Native node ⇒ Tier-2 worker; pure node ⇒ WASM cache; effect node ⇒ effect layer.
        let mut completed_effect_node_chirho = false;
        let (result_chirho, hit_chirho) = if def_chirho.is_builtin_phi_chirho() {
            cache_chirho::run_phi_node_cached_chirho(
                root_chirho,
                def_chirho,
                node_hash_chirho,
                &input_hashes_chirho,
                &parents_chirho,
            )?
        } else if contains_skipped_chirho {
            cache_chirho::run_skipped_node_cached_with_context_chirho(
                root_chirho,
                def_chirho,
                node_hash_chirho,
                &input_hashes_chirho,
                &parents_chirho,
                request_context_chirho,
            )?
        } else if input_hashes_chirho.len() > 1 {
            bail!(
                "multi-input execution is only supported by builtin phi nodes; '{}' has {} inputs",
                def_chirho.name_chirho,
                input_hashes_chirho.len()
            );
        } else if let Some(native_spec_chirho) =
            native_worker_chirho::native_node_spec_from_impl_chirho(&def_chirho.impl_wasm_chirho)
        {
            let in_hash_chirho = single_input_hash_chirho(&input_hashes_chirho)?;
            native_worker_chirho::validate_native_node_def_chirho(
                root_chirho,
                def_chirho,
                &native_spec_chirho,
            )?;
            if output_storage_chirho.private_subject_chirho().is_some() {
                bail!("private DAG edges from native nodes are not supported in v1");
            }
            native_worker_chirho::run_verified_native_node_cached_with_context_chirho(
                root_chirho,
                &native_spec_chirho,
                def_chirho,
                node_hash_chirho,
                in_hash_chirho,
                &parents_chirho,
                attribution_source_chirho,
            )?
        } else if def_chirho.is_pure_chirho() {
            let in_hash_chirho = single_input_hash_chirho(&input_hashes_chirho)?;
            let wasm_chirho = cas_chirho::get_chirho(root_chirho, &def_chirho.impl_wasm_chirho)
                .map_err(|e_chirho| {
                    anyhow!("loading wasm for '{}': {e_chirho}", def_chirho.name_chirho)
                })
                .map_err(|error_chirho| {
                    let identity_chirho = if progress_chirho.effect_completed_chirho {
                        DagExecutionRefusalIdentityChirho::DagPostEffectPureNodeRefusedChirho
                    } else {
                        DagExecutionRefusalIdentityChirho::DagPreEffectRefusedChirho
                    };
                    wrap_dag_execution_stage_chirho(identity_chirho, error_chirho)
                })?;
            cache_chirho::run_node_bytes_cached_with_value_storage_chirho(
                root_chirho,
                def_chirho,
                node_hash_chirho,
                &wasm_chirho,
                in_hash_chirho,
                &parents_chirho,
                cache_chirho::CachedValueStorageChirho {
                    resolver_chirho: &mut resolver_chirho,
                    output_storage_chirho: &output_storage_chirho,
                    attribution_source_chirho,
                },
            )
            .map_err(|error_chirho| {
                let identity_chirho = if progress_chirho.effect_completed_chirho {
                    DagExecutionRefusalIdentityChirho::DagPostEffectPureNodeRefusedChirho
                } else {
                    DagExecutionRefusalIdentityChirho::DagPreEffectRefusedChirho
                };
                wrap_dag_execution_stage_chirho(identity_chirho, error_chirho)
            })?
        } else {
            let in_hash_chirho = single_input_hash_chirho(&input_hashes_chirho)?;
            let effect_step_chirho = u32::try_from(node_step_chirho)
                .map_err(|_| anyhow!("DAG node step does not fit u32"))?;
            let result_chirho =
                effect_chirho::run_intent_chirho::with_run_intent_effect_invocation_chirho(
                node_hash_chirho,
                effect_step_chirho,
                || {
                    cache_chirho::run_effect_node_cached_with_context_value_storage_and_runtime_ports_chirho(
                            root_chirho,
                            def_chirho,
                              node_hash_chirho,
                              in_hash_chirho,
                              &parents_chirho,
                            cache_chirho::EffectNodeExecutionRuntimeChirho {
                                request_context_chirho,
                                storage_chirho: cache_chirho::CachedValueStorageChirho {
                                    resolver_chirho: &mut resolver_chirho,
                                    output_storage_chirho: &output_storage_chirho,
                                    attribution_source_chirho,
                                },
                                runtime_ports_chirho: runtime_ports_chirho.reborrow_chirho(),
                            },
                          )
                },
            )
            .map_err(|error_chirho| {
                ensure_dag_execution_stage_chirho(
                    DagExecutionRefusalIdentityChirho::DagEffectProviderRefusedChirho,
                    error_chirho,
                )
            })?;
            completed_effect_node_chirho = true;
            result_chirho
        };

        if completed_effect_node_chirho {
            progress_chirho.effect_completed_chirho = true;
        }

        for (port_chirho, hash_chirho) in &result_chirho.outputs_chirho {
            outputs_chirho.insert(
                (node_hash_chirho.clone(), port_chirho.clone()),
                hash_chirho.clone(),
            );
            note_dag_output_bytes_chirho(
                root_chirho,
                hash_chirho,
                &mut resolver_chirho,
                &mut aggregate_output_bytes_chirho,
                progress_chirho.output_bytes_cap_chirho,
            )
            .map_err(|error_chirho| {
                let identity_chirho = if completed_effect_node_chirho {
                    DagExecutionRefusalIdentityChirho::DagEffectResultAccountingRefusedChirho
                } else if progress_chirho.effect_completed_chirho {
                    DagExecutionRefusalIdentityChirho::DagPostEffectPureNodeRefusedChirho
                } else {
                    DagExecutionRefusalIdentityChirho::DagPreEffectRefusedChirho
                };
                wrap_dag_execution_stage_chirho(identity_chirho, error_chirho)
            })?;
        }
        run_of_chirho.insert(node_hash_chirho.clone(), result_chirho.run_chirho.clone());
        node_runs_chirho.push(NodeRunChirho {
            node_name_chirho: def_chirho.name_chirho.clone(),
            node_chirho: node_hash_chirho.clone(),
            run_chirho: result_chirho.run_chirho.clone(),
            cached_chirho: hit_chirho,
        });
    }

    let surface_identity_chirho = if progress_chirho.effect_completed_chirho {
        DagExecutionRefusalIdentityChirho::DagPostEffectSurfaceRefusedChirho
    } else {
        DagExecutionRefusalIdentityChirho::DagPreEffectRefusedChirho
    };
    let sink_chirho = sink_node_chirho(dag_chirho).map_err(|error_chirho| {
        wrap_dag_execution_stage_chirho(surface_identity_chirho, error_chirho)
    })?;
    let sink_def_chirho = defs_chirho
        .get(&sink_chirho)
        .ok_or_else(|| anyhow!("sink missing from defs"))
        .map_err(|error_chirho| {
            wrap_dag_execution_stage_chirho(surface_identity_chirho, error_chirho)
        })?;
    let sink_port_chirho = sink_def_chirho
        .outputs_chirho
        .first()
        .map(|p_chirho| p_chirho.name_chirho.clone())
        .ok_or_else(|| {
            anyhow!(
                "sink node '{}' has no output port",
                sink_def_chirho.name_chirho
            )
        })
        .map_err(|error_chirho| {
            wrap_dag_execution_stage_chirho(surface_identity_chirho, error_chirho)
        })?;
    let payload_hash_chirho = outputs_chirho
        .get(&(sink_chirho, sink_port_chirho))
        .ok_or_else(|| anyhow!("sink produced no output"))
        .map_err(|error_chirho| {
            wrap_dag_execution_stage_chirho(surface_identity_chirho, error_chirho)
        })?
        .clone();
    if cache_chirho::is_skipped_hash_chirho(root_chirho, &payload_hash_chirho).map_err(
        |error_chirho| wrap_dag_execution_stage_chirho(surface_identity_chirho, error_chirho),
    )? {
        return Err(wrap_dag_execution_stage_chirho(
            surface_identity_chirho,
            anyhow!("DAG surface output resolved to SkippedChirho"),
        ));
    }
    let payload_chirho = resolver_chirho
        .read_value_bytes_chirho(root_chirho, &payload_hash_chirho)
        .map_err(|error_chirho| {
            wrap_dag_execution_stage_chirho(surface_identity_chirho, error_chirho)
        })?;

    Ok(DagRunReportChirho {
        node_runs_chirho,
        payload_hash_chirho,
        payload_chirho,
    })
}

fn note_dag_output_bytes_chirho(
    root_chirho: &Path,
    output_hash_chirho: &HashChirho,
    resolver_chirho: &mut dag_private_value_chirho::PrivateDagValueResolverChirho,
    aggregate_output_bytes_chirho: &mut usize,
    output_bytes_cap_chirho: usize,
) -> Result<()> {
    if cache_chirho::is_skipped_hash_chirho(root_chirho, output_hash_chirho)? {
        return Ok(());
    }
    let output_bytes_chirho =
        resolver_chirho.read_value_bytes_chirho(root_chirho, output_hash_chirho)?;
    *aggregate_output_bytes_chirho = aggregate_output_bytes_chirho
        .checked_add(output_bytes_chirho.len())
        .ok_or_else(|| anyhow!("DAG run aggregate output bytes overflowed usize"))?;
    if *aggregate_output_bytes_chirho > output_bytes_cap_chirho {
        bail!(
            "DAG run output has {} aggregate bytes, over max {}",
            *aggregate_output_bytes_chirho,
            output_bytes_cap_chirho
        );
    }
    Ok(())
}

fn collect_edge_inputs_chirho(
    incoming_chirho: &[&EdgeChirho],
    outputs_chirho: &HashMap<(HashChirho, String), HashChirho>,
    run_of_chirho: &HashMap<HashChirho, HashChirho>,
    def_chirho: &NodeDefChirho,
    root_chirho: &Path,
    request_context_chirho: Option<&RequestContextChirho>,
    resolver_chirho: &mut dag_private_value_chirho::PrivateDagValueResolverChirho,
) -> Result<(BTreeMap<String, HashChirho>, Vec<HashChirho>)> {
    let mut inputs_chirho = BTreeMap::new();
    let mut parents_seen_chirho = BTreeSet::new();
    let mut parents_chirho = Vec::new();
    for edge_chirho in incoming_chirho {
        // The executor is the trust boundary, so an edge is checked against the node it feeds
        // HERE, not only where a DAG was authored: `build_dag_chirho` validates ports at build time,
        // but a stored DagChirho reaches this loop from any producer, and a phi whose declared
        // ports were all skipped would otherwise pass "exactly one live" on a port it never
        // declared and emit that value.
        if !def_chirho
            .inputs_chirho
            .iter()
            .any(|port_chirho| port_chirho.name_chirho == edge_chirho.to_port_chirho)
        {
            bail!(
                "edge {} targets input port '{}', which '{}' does not declare",
                edge_label_chirho(edge_chirho),
                edge_chirho.to_port_chirho,
                def_chirho.name_chirho
            );
        }
        let upstream_out_chirho = outputs_chirho
            .get(&(
                edge_chirho.from_node_chirho.clone(),
                edge_chirho.from_port_chirho.clone(),
            ))
            .ok_or_else(|| {
                anyhow!(
                    "edge into '{}' references an unproduced output",
                    def_chirho.name_chirho
                )
            })?
            .clone();
        if let Some((subject_chirho, owner_chirho)) =
            edge_private_subject_chirho(edge_chirho, request_context_chirho)?
        {
            // The record must VERIFY, not merely claim: the private-value log is parsed without
            // checking signatures, so one appended line naming this hash would otherwise satisfy
            // the gate that exists to prove a private edge's value was actually sealed.
            if dag_private_value_chirho::verified_private_dag_value_record_chirho(
                root_chirho,
                &upstream_out_chirho,
            )?
            .is_none()
                && !cache_chirho::is_skipped_hash_chirho(root_chirho, &upstream_out_chirho)?
            {
                bail!(
                    "private edge {} references value {} without a private DAG value record",
                    edge_label_chirho(edge_chirho),
                    upstream_out_chirho.0
                );
            }
            resolver_chirho.insert_private_hash_chirho(
                &subject_chirho,
                owner_chirho,
                &upstream_out_chirho,
            );
        }
        if inputs_chirho
            .insert(edge_chirho.to_port_chirho.clone(), upstream_out_chirho)
            .is_some()
        {
            bail!(
                "input port '{}' on '{}' has multiple producers",
                edge_chirho.to_port_chirho,
                def_chirho.name_chirho
            );
        }
        if let Some(parent_chirho) = run_of_chirho.get(&edge_chirho.from_node_chirho) {
            if parents_seen_chirho.insert(parent_chirho.clone()) {
                parents_chirho.push(parent_chirho.clone());
            }
        }
    }
    Ok((inputs_chirho, parents_chirho))
}

fn single_input_hash_chirho(inputs_chirho: &BTreeMap<String, HashChirho>) -> Result<&HashChirho> {
    inputs_chirho
        .values()
        .next()
        .ok_or_else(|| anyhow!("node has no input hash"))
}

fn node_output_port_chirho(def_chirho: &NodeDefChirho) -> String {
    def_chirho
        .outputs_chirho
        .first()
        .map(|port_chirho| port_chirho.name_chirho.clone())
        .unwrap_or_else(|| "out".to_string())
}

fn output_storage_policy_chirho(
    dag_chirho: &DagChirho,
    node_chirho: &HashChirho,
    port_chirho: &str,
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<dag_private_value_chirho::ValueStoragePolicyChirho> {
    let outgoing_chirho: Vec<&EdgeChirho> = dag_chirho
        .edges_chirho
        .iter()
        .filter(|edge_chirho| {
            &edge_chirho.from_node_chirho == node_chirho
                && edge_chirho.from_port_chirho == port_chirho
        })
        .collect();
    if outgoing_chirho.is_empty() {
        return Ok(dag_private_value_chirho::ValueStoragePolicyChirho::PublicCasChirho);
    }
    let mut private_subject_chirho: Option<(
        String,
        dag_private_value_chirho::PrivateValueOwnerChirho,
    )> = None;
    let mut public_count_chirho = 0usize;
    for edge_chirho in outgoing_chirho {
        match edge_private_subject_chirho(edge_chirho, request_context_chirho)? {
            Some(domain_chirho) => {
                if let Some(existing_chirho) = &private_subject_chirho {
                    if existing_chirho != &domain_chirho {
                        bail!(
                            "output {}:{} has private consumers with different subjects or owners",
                            node_chirho.0,
                            port_chirho
                        );
                    }
                } else {
                    private_subject_chirho = Some(domain_chirho);
                }
            }
            None => public_count_chirho += 1,
        }
    }
    match (private_subject_chirho, public_count_chirho) {
        (Some(_subject_chirho), n_chirho) if n_chirho > 0 => bail!(
            "output {}:{} has mixed private and public consumers; split the output before storing",
            node_chirho.0,
            port_chirho
        ),
        (Some((subject_chirho, owner_chirho)), _) => Ok(
            dag_private_value_chirho::ValueStoragePolicyChirho::PrivateBlobRefChirho {
                subject_chirho,
                owner_chirho,
            },
        ),
        (None, _) => Ok(dag_private_value_chirho::ValueStoragePolicyChirho::PublicCasChirho),
    }
}

/// The private domain (subject and owner source) a node inherits from its inputs. Inputs of two
/// different domains cannot combine, and an ambiguous input refuses (gpt #28935).
fn inherited_private_subject_chirho(
    input_hashes_chirho: &BTreeMap<String, HashChirho>,
    resolver_chirho: &dag_private_value_chirho::PrivateDagValueResolverChirho,
) -> Result<Option<(String, dag_private_value_chirho::PrivateValueOwnerChirho)>> {
    let mut inherited_chirho: Option<(String, dag_private_value_chirho::PrivateValueOwnerChirho)> =
        None;
    for input_hash_chirho in input_hashes_chirho.values() {
        let Some(domain_chirho) = resolver_chirho.domain_for_hash_chirho(input_hash_chirho)? else {
            continue;
        };
        if let Some(existing_chirho) = &inherited_chirho {
            if existing_chirho != &domain_chirho {
                bail!("a node cannot combine private DAG inputs of different subjects or owners");
            }
        } else {
            inherited_chirho = Some(domain_chirho);
        }
    }
    Ok(inherited_chirho)
}

/// An output keeps the private domain it inherits: a public declaration becomes that domain, and a
/// private declaration must name the SAME subject and owner source. A same-subject declaration with a
/// different owner is a rebinding, not a coincidence to pass (gpt #28935).
fn propagated_output_storage_policy_chirho(
    declared_chirho: dag_private_value_chirho::ValueStoragePolicyChirho,
    inherited_chirho: Option<(String, dag_private_value_chirho::PrivateValueOwnerChirho)>,
    node_chirho: &HashChirho,
    port_chirho: &str,
) -> Result<dag_private_value_chirho::ValueStoragePolicyChirho> {
    let Some((inherited_subject_chirho, inherited_owner_chirho)) = inherited_chirho else {
        return Ok(declared_chirho);
    };
    match declared_chirho {
        dag_private_value_chirho::ValueStoragePolicyChirho::PublicCasChirho => Ok(
            dag_private_value_chirho::ValueStoragePolicyChirho::PrivateBlobRefChirho {
                subject_chirho: inherited_subject_chirho,
                owner_chirho: inherited_owner_chirho,
            },
        ),
        dag_private_value_chirho::ValueStoragePolicyChirho::PrivateBlobRefChirho {
            subject_chirho,
            owner_chirho,
        } if subject_chirho == inherited_subject_chirho
            && owner_chirho == inherited_owner_chirho =>
        {
            Ok(
                dag_private_value_chirho::ValueStoragePolicyChirho::PrivateBlobRefChirho {
                    subject_chirho,
                    owner_chirho,
                },
            )
        }
        dag_private_value_chirho::ValueStoragePolicyChirho::PrivateBlobRefChirho { .. } => bail!(
            "output {}:{} cannot rebind inherited private data to a different subject or owner",
            node_chirho.0,
            port_chirho
        ),
    }
}

fn validate_viewer_state_input_privacy_chirho(
    dag_chirho: &DagChirho,
    defs_chirho: &HashMap<HashChirho, NodeDefChirho>,
    input_value_chirho: &DagInputValueChirho,
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<()> {
    let has_viewer_state_effect_chirho =
        defs_chirho.values().any(|def_chirho| {
            def_chirho.capabilities_chirho.iter().any(|capability_chirho| {
            matches!(
                capability_chirho,
                crate::model_chirho::CapabilityChirho::ReadStoreChirho { prefix_chirho }
                    | crate::model_chirho::CapabilityChirho::WriteStoreChirho { prefix_chirho }
                    if prefix_chirho
                        .starts_with(effect_chirho::viewer_state_capability_prefix_chirho())
            )
        })
        });
    let request_context_chirho = if has_viewer_state_effect_chirho {
        Some(
            request_context_chirho
                .ok_or_else(|| anyhow!("viewer-state DAG requires a signed-in request user"))?,
        )
    } else {
        request_context_chirho
    };

    for node_hash_chirho in &dag_chirho.nodes_chirho {
        let def_chirho = defs_chirho
            .get(node_hash_chirho)
            .ok_or_else(|| anyhow!("node {} missing from defs", node_hash_chirho.0))?;
        let viewer_state_effect_chirho = def_chirho.capabilities_chirho.iter().any(
            |capability_chirho| {
                matches!(
                    capability_chirho,
                    crate::model_chirho::CapabilityChirho::ReadStoreChirho { prefix_chirho }
                        | crate::model_chirho::CapabilityChirho::WriteStoreChirho { prefix_chirho }
                        if prefix_chirho
                            .starts_with(effect_chirho::viewer_state_capability_prefix_chirho())
                )
            },
        );
        if !viewer_state_effect_chirho {
            continue;
        }

        let incoming_chirho: Vec<&EdgeChirho> = dag_chirho
            .edges_chirho
            .iter()
            .filter(|edge_chirho| &edge_chirho.to_node_chirho == node_hash_chirho)
            .collect();
        if incoming_chirho.is_empty() {
            let context_chirho = request_context_chirho
                .expect("viewer-state request context was established before node validation");
            match input_value_chirho {
                DagInputValueChirho::PrivateBytesChirho { subject_chirho, .. }
                    if subject_chirho == &context_chirho.user_principal_chirho => {}
                _ => bail!(
                    "viewer-state DAG input must use the signed-in request user's private input plane"
                ),
            }
            continue;
        }

        if incoming_chirho.iter().any(|edge_chirho| {
            !matches!(
                edge_chirho.privacy_chirho,
                Some(
                    crate::model_chirho::EdgePrivacyChirho::PrivateBlobRefChirho {
                        subject_source_chirho:
                            crate::model_chirho::EdgePrivacySubjectSourceChirho::RequestUserChirho,
                    }
                )
            )
        }) {
            bail!(
                "viewer-state effect node '{}' requires request-user-private input edges",
                def_chirho.name_chirho
            );
        }
    }
    Ok(())
}

/// An edge's private subject and its owner source: a request-user edge is the actor's own data; an
/// app-subject or static edge is in the app owner's container.
fn edge_private_subject_chirho(
    edge_chirho: &EdgeChirho,
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<Option<(String, dag_private_value_chirho::PrivateValueOwnerChirho)>> {
    let Some(privacy_chirho) = &edge_chirho.privacy_chirho else {
        return Ok(None);
    };
    match privacy_chirho {
        crate::model_chirho::EdgePrivacyChirho::PrivateBlobRefChirho {
            subject_source_chirho,
        } => match subject_source_chirho {
            crate::model_chirho::EdgePrivacySubjectSourceChirho::RequestUserChirho => {
                let context_chirho = request_context_chirho.ok_or_else(|| {
                    anyhow!(
                        "private DAG edge {} requires a signed-in request user",
                        edge_label_chirho(edge_chirho)
                    )
                })?;
                Ok(Some((
                    context_chirho.user_principal_chirho.clone(),
                    dag_private_value_chirho::PrivateValueOwnerChirho::RequestActorChirho,
                )))
            }
            crate::model_chirho::EdgePrivacySubjectSourceChirho::AppSubjectChirho => {
                let context_chirho = request_context_chirho.ok_or_else(|| {
                    anyhow!(
                        "private DAG edge {} requires app request context",
                        edge_label_chirho(edge_chirho)
                    )
                })?;
                Ok(Some((
                    format!("app-subject-chirho:{}", context_chirho.app_chirho),
                    dag_private_value_chirho::PrivateValueOwnerChirho::AppContainerChirho,
                )))
            }
            crate::model_chirho::EdgePrivacySubjectSourceChirho::StaticSubjectChirho {
                subject_chirho,
            } => Ok(Some((
                subject_chirho.clone(),
                dag_private_value_chirho::PrivateValueOwnerChirho::AppContainerChirho,
            ))),
        },
    }
}

fn edge_label_chirho(edge_chirho: &EdgeChirho) -> String {
    format!(
        "{}:{}->{}:{}",
        edge_chirho.from_node_chirho.0,
        edge_chirho.from_port_chirho,
        edge_chirho.to_node_chirho.0,
        edge_chirho.to_port_chirho
    )
}

/// Kahn topological order over the DAG's nodes; errors on a cycle or dangling edge.
fn topo_order_chirho(dag_chirho: &DagChirho) -> Result<Vec<HashChirho>> {
    let mut indegree_chirho: HashMap<HashChirho, usize> = HashMap::new();
    for node_chirho in &dag_chirho.nodes_chirho {
        indegree_chirho.entry(node_chirho.clone()).or_insert(0);
    }
    for edge_chirho in &dag_chirho.edges_chirho {
        *indegree_chirho
            .entry(edge_chirho.to_node_chirho.clone())
            .or_insert(0) += 1;
    }

    let mut queue_chirho: VecDeque<HashChirho> = dag_chirho
        .nodes_chirho
        .iter()
        .filter(|node_chirho| indegree_chirho.get(*node_chirho).copied().unwrap_or(0) == 0)
        .cloned()
        .collect();

    let mut order_chirho: Vec<HashChirho> = Vec::new();
    while let Some(node_chirho) = queue_chirho.pop_front() {
        order_chirho.push(node_chirho.clone());
        for edge_chirho in dag_chirho
            .edges_chirho
            .iter()
            .filter(|edge_chirho| edge_chirho.from_node_chirho == node_chirho)
        {
            if let Some(degree_chirho) = indegree_chirho.get_mut(&edge_chirho.to_node_chirho) {
                *degree_chirho -= 1;
                if *degree_chirho == 0 {
                    queue_chirho.push_back(edge_chirho.to_node_chirho.clone());
                }
            }
        }
    }

    if order_chirho.len() != dag_chirho.nodes_chirho.len() {
        bail!("DAG has a cycle (or a dangling edge); topological order is incomplete");
    }
    Ok(order_chirho)
}

/// The single sink node (no outgoing edges). v1 expects exactly one.
fn sink_node_chirho(dag_chirho: &DagChirho) -> Result<HashChirho> {
    let sinks_chirho: Vec<HashChirho> = dag_chirho
        .nodes_chirho
        .iter()
        .filter(|node_chirho| {
            !dag_chirho
                .edges_chirho
                .iter()
                .any(|edge_chirho| &edge_chirho.from_node_chirho == *node_chirho)
        })
        .cloned()
        .collect();
    match sinks_chirho.len() {
        1 => Ok(sinks_chirho.into_iter().next().unwrap()),
        0 => bail!("DAG has no sink node (every node has an outgoing edge)"),
        n_chirho => bail!("v1 DAG executor expects a single sink; found {n_chirho}"),
    }
}

#[cfg(test)]
#[path = "dag_chirho/tests_chirho.rs"]
pub(crate) mod tests_chirho;

#[cfg(test)]
#[path = "dag_chirho/execution_stage_tests_chirho.rs"]
mod execution_stage_tests_chirho;

#[cfg(test)]
#[path = "dag_chirho/private_edge_verified_record_tests_chirho.rs"]
mod private_edge_verified_record_tests_chirho;

#[cfg(test)]
#[path = "dag_chirho/viewer_state_privacy_tests_chirho.rs"]
mod viewer_state_privacy_tests_chirho;

#[cfg(test)]
#[path = "dag_chirho/phi_private_branch_tests_chirho.rs"]
mod phi_private_branch_tests_chirho;

#[cfg(test)]
#[path = "dag_chirho/owner_source_tests_chirho.rs"]
mod owner_source_tests_chirho;
