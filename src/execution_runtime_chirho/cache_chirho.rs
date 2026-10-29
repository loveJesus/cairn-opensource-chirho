// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The result cache + the run path — the keystone view of the Merkle DAG.
//!
//! A run is fully described by `RunKeyChirho` = (node identity, input hashes, caps). Its hash
//! is the run id: cache key, version coordinate, and audit address at once. A **pure** node
//! with a seen run-key returns its stored `RunResultChirho` without executing; a miss runs
//! the node in the sandbox, stores outputs + a trace, persists the result, and returns it.
//! An **effect** node runs the blessed effect layer instead, recording the `EffectChirho`.

use crate::model_chirho::{
    CapabilityChirho, HashChirho, NodeDefChirho, RequestContextChirho, RunKeyChirho,
    RunResultChirho, RunStatusChirho, SKIPPED_STONE_BYTES_CHIRHO,
};
use crate::{
    blessed_chirho, cas_chirho, dag_private_value_chirho, durable_chirho, effect_chirho,
    runner_chirho, store_chirho,
};
use anyhow::{anyhow, bail, Context, Result};
use cairn_signer_chirho::signer_chirho;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const RUN_RESULT_SEAL_SCHEMA_CHIRHO: &str = "run-result-seal-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct RunResultSealChirho {
    schema_chirho: String,
    run_chirho: HashChirho,
    result_hash_chirho: HashChirho,
    sig_chirho: String,
}

/// A run result is addressed by its run id (= hash of its `RunKeyChirho`).
fn run_path_chirho(root_chirho: &Path, run_hash_chirho: &HashChirho) -> PathBuf {
    root_chirho.join("runs-chirho").join(&run_hash_chirho.0)
}

fn run_result_seal_path_chirho(root_chirho: &Path, run_hash_chirho: &HashChirho) -> PathBuf {
    root_chirho.join("runseals-chirho").join(&run_hash_chirho.0)
}

fn run_key_path_chirho(root_chirho: &Path, run_hash_chirho: &HashChirho) -> PathBuf {
    root_chirho.join("runkeys-chirho").join(&run_hash_chirho.0)
}

/// The `RunKeyChirho` for applying `node` (by its hash) to a scalar `input`.
fn build_run_key_chirho(
    node_def_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
    input_chirho: i64,
) -> Result<RunKeyChirho> {
    let port_name_chirho = node_def_chirho
        .inputs_chirho
        .first()
        .map(|p_chirho| p_chirho.name_chirho.clone())
        .unwrap_or_else(|| "in".to_string());
    let mut inputs_chirho = BTreeMap::new();
    inputs_chirho.insert(
        port_name_chirho,
        store_chirho::hash_object_chirho(&input_chirho)?,
    );
    let caps_hash_chirho = store_chirho::hash_object_chirho(&node_def_chirho.capabilities_chirho)?;
    Ok(RunKeyChirho {
        node_chirho: node_hash_chirho.clone(),
        inputs_chirho,
        caps_chirho: caps_hash_chirho,
    })
}

/// The run id (cache key) for applying `node` to a scalar `input` — hash(RunKeyChirho).
pub fn run_key_hash_chirho(
    node_def_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
    input_chirho: i64,
) -> Result<HashChirho> {
    store_chirho::hash_object_chirho(&build_run_key_chirho(
        node_def_chirho,
        node_hash_chirho,
        input_chirho,
    )?)
}

/// Load a stored `RunResultChirho` by its run id, if present.
pub fn load_result_chirho(
    root_chirho: &Path,
    run_hash_chirho: &HashChirho,
) -> Result<Option<RunResultChirho>> {
    let path_chirho = run_path_chirho(root_chirho, run_hash_chirho);
    if !path_chirho.exists() {
        return Ok(None);
    }
    let bytes_chirho =
        std::fs::read(&path_chirho).with_context(|| format!("read {}", path_chirho.display()))?;
    Ok(Some(
        serde_json::from_slice(&bytes_chirho).context("decode RunResultChirho")?,
    ))
}

pub(crate) fn load_sealed_result_chirho(
    root_chirho: &Path,
    run_hash_chirho: &HashChirho,
) -> Result<Option<RunResultChirho>> {
    let Some(result_chirho) = load_result_chirho(root_chirho, run_hash_chirho)? else {
        return Ok(None);
    };
    verify_run_result_seal_chirho(root_chirho, run_hash_chirho, &result_chirho)?;
    Ok(Some(result_chirho))
}

pub(crate) fn load_resealable_pure_result_chirho(
    root_chirho: &Path,
    run_hash_chirho: &HashChirho,
) -> Result<Option<RunResultChirho>> {
    let Some(result_chirho) = load_result_chirho(root_chirho, run_hash_chirho)? else {
        return Ok(None);
    };
    if !run_result_seal_path_chirho(root_chirho, run_hash_chirho).exists() {
        return Ok(None);
    }
    verify_run_result_seal_chirho(root_chirho, run_hash_chirho, &result_chirho)?;
    Ok(Some(result_chirho))
}

pub fn load_run_key_chirho(
    root_chirho: &Path,
    run_hash_chirho: &HashChirho,
) -> Result<Option<RunKeyChirho>> {
    let path_chirho = run_key_path_chirho(root_chirho, run_hash_chirho);
    if !path_chirho.exists() {
        return Ok(None);
    }
    let bytes_chirho =
        std::fs::read(&path_chirho).with_context(|| format!("read {}", path_chirho.display()))?;
    Ok(Some(
        serde_json::from_slice(&bytes_chirho).context("decode RunKeyChirho")?,
    ))
}

/// Store a run's key, writing only when the present key's bytes differ (both the WASM and the
/// native cached paths).
///
/// A run hash names exactly one key, so bytes already equal at its path are the only correct
/// content, and a cached run, which stores its key before every lookup, then writes nothing.
/// Absent, different (a key from an older encoding) or unreadable is written durably as before. The
/// comparison follows no symlink and never waits on a FIFO or other special file (ordinary filesystem
/// latency is not bounded here), and a symlink, FIFO or other non-regular file in the key's place is
/// replaced by the durable write, its target untouched.
/// Workflow: spec-chirho/tasklists-chirho/26-10-04_14-55-tasklist-served_overload_followups-chirho.md (cache hits).
pub(crate) fn store_run_key_chirho(
    root_chirho: &Path,
    run_hash_chirho: &HashChirho,
    key_chirho: &RunKeyChirho,
) -> Result<()> {
    let path_chirho = run_key_path_chirho(root_chirho, run_hash_chirho);
    let bytes_chirho = serde_json::to_vec_pretty(key_chirho).context("encode RunKeyChirho")?;
    // Compared through the durable crate's identity-stable bounded reader (PFE #26446): no symlink is
    // followed, the open never waits on a FIFO or other special file (one is refused at once; ordinary
    // filesystem latency is not bounded here), only a regular single-link file is read, and never more
    // than the key's length plus one byte.
    let unchanged_chirho = durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        &path_chirho,
        bytes_chirho.len() as u64,
    )
    .is_ok_and(|present_chirho| present_chirho == bytes_chirho);
    if unchanged_chirho {
        return Ok(());
    }
    if let Some(parent_chirho) = path_chirho.parent() {
        std::fs::create_dir_all(parent_chirho)?;
    }
    durable_chirho::write_file_durable_chirho(&path_chirho, &bytes_chirho)
        .context("write RunKeyChirho")?;
    Ok(())
}

pub(crate) fn store_result_chirho(
    root_chirho: &Path,
    result_chirho: &RunResultChirho,
) -> Result<()> {
    store_run_result_seal_chirho(root_chirho, result_chirho)?;
    let path_chirho = run_path_chirho(root_chirho, &result_chirho.run_chirho);
    if let Some(parent_chirho) = path_chirho.parent() {
        std::fs::create_dir_all(parent_chirho)?;
    }
    let bytes_chirho =
        serde_json::to_vec_pretty(result_chirho).context("encode RunResultChirho")?;
    durable_chirho::write_file_durable_chirho(&path_chirho, &bytes_chirho)
        .context("write RunResultChirho")?;
    Ok(())
}

fn store_run_result_seal_chirho(root_chirho: &Path, result_chirho: &RunResultChirho) -> Result<()> {
    let path_chirho = run_result_seal_path_chirho(root_chirho, &result_chirho.run_chirho);
    if let Some(parent_chirho) = path_chirho.parent() {
        std::fs::create_dir_all(parent_chirho)?;
    }
    let mut seal_chirho = RunResultSealChirho {
        schema_chirho: RUN_RESULT_SEAL_SCHEMA_CHIRHO.to_string(),
        run_chirho: result_chirho.run_chirho.clone(),
        result_hash_chirho: store_chirho::hash_object_chirho(result_chirho)?,
        sig_chirho: String::new(),
    };
    let message_chirho = run_result_seal_message_chirho(&seal_chirho)?;
    seal_chirho.sig_chirho = signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
    let bytes_chirho =
        serde_json::to_vec_pretty(&seal_chirho).context("encode RunResultSealChirho")?;
    durable_chirho::write_file_durable_chirho(&path_chirho, &bytes_chirho)
        .context("write RunResultSealChirho")?;
    Ok(())
}

pub(crate) fn verify_run_result_seal_chirho(
    root_chirho: &Path,
    expected_run_chirho: &HashChirho,
    result_chirho: &RunResultChirho,
) -> Result<()> {
    if &result_chirho.run_chirho != expected_run_chirho {
        bail!(
            "run result cache key mismatch: queried {} but result declares {}",
            expected_run_chirho.0,
            result_chirho.run_chirho.0
        );
    }
    let path_chirho = run_result_seal_path_chirho(root_chirho, expected_run_chirho);
    if !path_chirho.exists() {
        bail!(
            "run {} is missing signed RunResultChirho seal",
            expected_run_chirho.0
        );
    }
    let bytes_chirho =
        std::fs::read(&path_chirho).with_context(|| format!("read {}", path_chirho.display()))?;
    let seal_chirho: RunResultSealChirho =
        serde_json::from_slice(&bytes_chirho).context("decode RunResultSealChirho")?;
    if seal_chirho.schema_chirho != RUN_RESULT_SEAL_SCHEMA_CHIRHO {
        bail!(
            "run {} RunResultChirho seal schema '{}' is unsupported",
            expected_run_chirho.0,
            seal_chirho.schema_chirho
        );
    }
    if &seal_chirho.run_chirho != expected_run_chirho {
        bail!(
            "run result seal key mismatch: queried {} but seal declares {}",
            expected_run_chirho.0,
            seal_chirho.run_chirho.0
        );
    }
    let actual_hash_chirho = store_chirho::hash_object_chirho(result_chirho)?;
    if seal_chirho.result_hash_chirho != actual_hash_chirho {
        bail!(
            "run result seal hash mismatch: run {} seal covers {} but result hashes to {}",
            expected_run_chirho.0,
            seal_chirho.result_hash_chirho.0,
            actual_hash_chirho.0
        );
    }
    let message_chirho = run_result_seal_message_chirho(&seal_chirho)?;
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    if !signer_chirho::verify_with_pubkey_chirho(
        &pubkey_chirho,
        &message_chirho,
        &seal_chirho.sig_chirho,
    )? {
        bail!(
            "run {} RunResultChirho seal signature invalid",
            expected_run_chirho.0
        );
    }
    Ok(())
}

fn run_result_seal_message_chirho(seal_chirho: &RunResultSealChirho) -> Result<Vec<u8>> {
    serde_json::to_vec(&(
        &seal_chirho.schema_chirho,
        &seal_chirho.run_chirho,
        &seal_chirho.result_hash_chirho,
    ))
    .context("encode RunResultSealChirho message")
}

/// Run a pure scalar (`i64 -> i64`) node, using the cache.
pub fn run_node_cached_chirho(
    root_chirho: &Path,
    node_def_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
    wasm_chirho: &[u8],
    input_chirho: i64,
) -> Result<(RunResultChirho, bool)> {
    let key_chirho = build_run_key_chirho(node_def_chirho, node_hash_chirho, input_chirho)?;
    let run_hash_chirho = store_chirho::hash_object_chirho(&key_chirho)?;
    store_run_key_chirho(root_chirho, &run_hash_chirho, &key_chirho)?;

    if let Some(cached_chirho) = load_resealable_pure_result_chirho(root_chirho, &run_hash_chirho)?
    {
        return Ok((cached_chirho, true));
    }

    let outcome_chirho = runner_chirho::run_node_with_limits_chirho(
        wasm_chirho,
        &node_def_chirho.entry_chirho,
        input_chirho,
        node_def_chirho.fuel_limit_chirho,
        usize_node_limit_chirho(node_def_chirho.max_memory_bytes_chirho)?,
    )?;

    let out_hash_chirho =
        store_chirho::put_object_chirho(root_chirho, &outcome_chirho.result_chirho)?;
    let out_port_chirho = output_port_chirho(node_def_chirho);
    let mut outputs_chirho = BTreeMap::new();
    outputs_chirho.insert(out_port_chirho, out_hash_chirho);

    let trace_text_chirho = format!(
        "node={} entry={} input={} output={} fuel_used={}",
        node_def_chirho.name_chirho,
        node_def_chirho.entry_chirho,
        input_chirho,
        outcome_chirho.result_chirho,
        outcome_chirho.fuel_used_chirho
    );
    let trace_hash_chirho = cas_chirho::add_chirho(root_chirho, trace_text_chirho.as_bytes())?;

    let result_chirho = RunResultChirho {
        run_chirho: run_hash_chirho,
        outputs_chirho,
        effects_chirho: vec![],
        fuel_used_chirho: outcome_chirho.fuel_used_chirho,
        trace_chirho: trace_hash_chirho,
        status_chirho: RunStatusChirho::OkChirho,
        parents_chirho: vec![],
    };
    store_result_chirho(root_chirho, &result_chirho)?;
    Ok((result_chirho, false))
}

/// The `RunKeyChirho` for applying `node` to an input identified by its content hash.
fn build_bytes_run_key_chirho(
    node_def_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
    input_hash_chirho: &HashChirho,
) -> Result<RunKeyChirho> {
    let port_name_chirho = node_def_chirho
        .inputs_chirho
        .first()
        .map(|p_chirho| p_chirho.name_chirho.clone())
        .unwrap_or_else(|| "in".to_string());
    let mut inputs_chirho = BTreeMap::new();
    inputs_chirho.insert(port_name_chirho, input_hash_chirho.clone());
    build_bytes_run_key_for_inputs_chirho(node_def_chirho, node_hash_chirho, &inputs_chirho)
}

pub(crate) fn build_bytes_run_key_for_inputs_chirho(
    node_def_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
    inputs_chirho: &BTreeMap<String, HashChirho>,
) -> Result<RunKeyChirho> {
    let caps_hash_chirho = store_chirho::hash_object_chirho(&node_def_chirho.capabilities_chirho)?;
    Ok(RunKeyChirho {
        node_chirho: node_hash_chirho.clone(),
        inputs_chirho: inputs_chirho.clone(),
        caps_chirho: caps_hash_chirho,
    })
}

fn output_port_chirho(node_def_chirho: &NodeDefChirho) -> String {
    node_def_chirho
        .outputs_chirho
        .first()
        .map(|p_chirho| p_chirho.name_chirho.clone())
        .unwrap_or_else(|| "out".to_string())
}

fn output_ports_chirho(node_def_chirho: &NodeDefChirho) -> Vec<String> {
    node_def_chirho
        .outputs_chirho
        .iter()
        .map(|port_chirho| port_chirho.name_chirho.clone())
        .collect()
}

pub(crate) fn skipped_stone_hash_chirho(root_chirho: &Path) -> Result<HashChirho> {
    Ok(cas_chirho::add_chirho(
        root_chirho,
        SKIPPED_STONE_BYTES_CHIRHO,
    )?)
}

pub(crate) fn is_skipped_hash_chirho(root_chirho: &Path, hash_chirho: &HashChirho) -> Result<bool> {
    Ok(hash_chirho == &skipped_stone_hash_chirho(root_chirho)?)
}

pub(crate) fn run_skipped_node_cached_with_context_chirho(
    root_chirho: &Path,
    node_def_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
    inputs_chirho: &BTreeMap<String, HashChirho>,
    parents_chirho: &[HashChirho],
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<(RunResultChirho, bool)> {
    // A pure node stays pure under a request context. The contextual def exists to bind an
    // EFFECT node's caller into its capabilities and run key; applied to a pure node it adds the
    // identity/app-context capabilities, which made the skipped path read every pure node on an
    // authenticated route as an effect node with no executable capability and refuse the skip.
    // Part of `spec-chirho/workflows-chirho/private-dag-edge-values-chirho.md`.
    let effective_def_chirho = if node_def_chirho.is_pure_chirho() {
        node_def_chirho.clone()
    } else {
        contextual_node_def_chirho(node_def_chirho, request_context_chirho)
    };
    let key_chirho = build_bytes_run_key_for_inputs_chirho(
        &effective_def_chirho,
        node_hash_chirho,
        inputs_chirho,
    )?;
    let run_hash_chirho = store_chirho::hash_object_chirho(&key_chirho)?;
    store_run_key_chirho(root_chirho, &run_hash_chirho, &key_chirho)?;

    if let Some(cached_chirho) = load_sealed_result_chirho(root_chirho, &run_hash_chirho)? {
        let cached_chirho =
            cached_with_current_parents_chirho(root_chirho, cached_chirho, parents_chirho)?;
        return Ok((cached_chirho, true));
    }

    let skipped_hash_chirho = skipped_stone_hash_chirho(root_chirho)?;
    let mut outputs_chirho = BTreeMap::new();
    for port_chirho in output_ports_chirho(node_def_chirho) {
        outputs_chirho.insert(port_chirho, skipped_hash_chirho.clone());
    }

    let effects_chirho = if effective_def_chirho.is_pure_chirho() {
        Vec::new()
    } else {
        let capability_chirho = executable_effect_capability_chirho(&effective_def_chirho)?;
        enforce_identity_for_paid_effect_chirho(&effective_def_chirho, &capability_chirho)?;
        vec![effect_chirho::signed_skipped_effect_chirho(
            root_chirho,
            run_hash_chirho.clone(),
            capability_chirho,
            &skipped_hash_chirho,
            &skipped_hash_chirho,
        )?]
    };

    let trace_text_chirho = format!(
        "skipped node={} reason=skipped-input inputs={:?}",
        effective_def_chirho.name_chirho, inputs_chirho
    );
    let trace_hash_chirho = cas_chirho::add_chirho(root_chirho, trace_text_chirho.as_bytes())?;
    let result_chirho = RunResultChirho {
        run_chirho: run_hash_chirho,
        outputs_chirho,
        effects_chirho,
        fuel_used_chirho: 0,
        trace_chirho: trace_hash_chirho,
        status_chirho: RunStatusChirho::SkippedChirho {
            reason_chirho: "skipped-input-chirho".to_string(),
        },
        parents_chirho: parents_chirho.to_vec(),
    };
    store_result_chirho(root_chirho, &result_chirho)?;
    Ok((result_chirho, false))
}

/// Run a pure **bytes** node, using the cache. The input is given by its content hash;
/// `parents` are the upstream run ids feeding this node (the provenance edges).
pub fn run_node_bytes_cached_chirho(
    root_chirho: &Path,
    node_def_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
    wasm_chirho: &[u8],
    input_hash_chirho: &HashChirho,
    parents_chirho: &[HashChirho],
) -> Result<(RunResultChirho, bool)> {
    let mut resolver_chirho = dag_private_value_chirho::PrivateDagValueResolverChirho::default();
    run_node_bytes_cached_with_value_storage_chirho(
        root_chirho,
        node_def_chirho,
        node_hash_chirho,
        wasm_chirho,
        input_hash_chirho,
        parents_chirho,
        CachedValueStorageChirho {
            resolver_chirho: &mut resolver_chirho,
            output_storage_chirho:
                &dag_private_value_chirho::ValueStoragePolicyChirho::PublicCasChirho,
            attribution_source_chirho:
                dag_private_value_chirho::RunAttributionSourceChirho::new_chirho(None, None),
        },
    )
}

pub struct CachedValueStorageChirho<'a> {
    pub resolver_chirho: &'a mut dag_private_value_chirho::PrivateDagValueResolverChirho,
    pub output_storage_chirho: &'a dag_private_value_chirho::ValueStoragePolicyChirho,
    /// Whose container the node's private outputs join: its run's request, or its run's declaration.
    pub attribution_source_chirho: dag_private_value_chirho::RunAttributionSourceChirho<'a>,
}

fn bind_cached_outputs_chirho(
    root_chirho: &Path,
    result_chirho: &RunResultChirho,
    storage_chirho: &mut CachedValueStorageChirho<'_>,
) -> Result<bool> {
    let Some((subject_chirho, owner_chirho)) =
        storage_chirho.output_storage_chirho.private_domain_chirho()
    else {
        for output_hash_chirho in result_chirho.outputs_chirho.values() {
            if is_skipped_hash_chirho(root_chirho, output_hash_chirho)? {
                continue;
            }
            match cas_chirho::read_verified_chirho(root_chirho, output_hash_chirho) {
                cas_chirho::CasReadOutcomeChirho::VerifiedChirho(_) => {}
                cas_chirho::CasReadOutcomeChirho::AbsentChirho(_) => return Ok(false),
                cas_chirho::CasReadOutcomeChirho::TamperedChirho { actual_chirho } => {
                    bail!(
                        "cached output {} content address mismatch: actual {}",
                        output_hash_chirho.0,
                        actual_chirho.0
                    );
                }
                cas_chirho::CasReadOutcomeChirho::UnreadableChirho(error_chirho) => {
                    return Err(error_chirho).with_context(|| {
                        format!("cached output {} is unreadable", output_hash_chirho.0)
                    });
                }
            }
        }
        return Ok(true);
    };
    for output_hash_chirho in result_chirho.outputs_chirho.values() {
        if is_skipped_hash_chirho(root_chirho, output_hash_chirho)? {
            continue;
        }
        if dag_private_value_chirho::verified_private_dag_value_record_for_subject_chirho(
            root_chirho,
            subject_chirho,
            output_hash_chirho,
        )?
        .is_none()
        {
            return Ok(false);
        }
    }
    for output_hash_chirho in result_chirho.outputs_chirho.values() {
        if !is_skipped_hash_chirho(root_chirho, output_hash_chirho)? {
            storage_chirho.resolver_chirho.insert_private_hash_chirho(
                subject_chirho,
                owner_chirho,
                output_hash_chirho,
            );
        }
    }
    Ok(true)
}

pub fn run_node_bytes_cached_with_value_storage_chirho(
    root_chirho: &Path,
    node_def_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
    wasm_chirho: &[u8],
    input_hash_chirho: &HashChirho,
    parents_chirho: &[HashChirho],
    mut storage_chirho: CachedValueStorageChirho<'_>,
) -> Result<(RunResultChirho, bool)> {
    let key_chirho =
        build_bytes_run_key_chirho(node_def_chirho, node_hash_chirho, input_hash_chirho)?;
    let run_hash_chirho = store_chirho::hash_object_chirho(&key_chirho)?;
    store_run_key_chirho(root_chirho, &run_hash_chirho, &key_chirho)?;

    if let Some(cached_chirho) = load_resealable_pure_result_chirho(root_chirho, &run_hash_chirho)?
    {
        let cached_chirho =
            cached_with_current_parents_chirho(root_chirho, cached_chirho, parents_chirho)?;
        if bind_cached_outputs_chirho(root_chirho, &cached_chirho, &mut storage_chirho)? {
            return Ok((cached_chirho, true));
        }
    }
    let input_bytes_chirho = storage_chirho
        .resolver_chirho
        .read_value_bytes_chirho(root_chirho, input_hash_chirho)?;
    let outcome_chirho = runner_chirho::run_node_bytes_with_limits_chirho(
        wasm_chirho,
        &node_def_chirho.entry_chirho,
        &input_bytes_chirho,
        node_def_chirho.fuel_limit_chirho,
        usize_node_limit_chirho(node_def_chirho.max_output_bytes_chirho)?,
        usize_node_limit_chirho(node_def_chirho.max_memory_bytes_chirho)?,
    )?;

    let out_hash_chirho = dag_private_value_chirho::store_dag_value_with_policy_chirho(
        root_chirho,
        &outcome_chirho.output_chirho,
        storage_chirho.output_storage_chirho,
        dag_private_value_chirho::PrivateDagValueContextChirho {
            node_chirho: Some(node_hash_chirho.clone()),
            port_chirho: Some(output_port_chirho(node_def_chirho)),
            ..Default::default()
        },
        Some(storage_chirho.resolver_chirho),
        &storage_chirho.attribution_source_chirho,
    )?;
    let mut outputs_chirho = BTreeMap::new();
    outputs_chirho.insert(output_port_chirho(node_def_chirho), out_hash_chirho);

    let trace_text_chirho = format!(
        "node={} entry={} in={} out_len={} fuel_used={}",
        node_def_chirho.name_chirho,
        node_def_chirho.entry_chirho,
        input_hash_chirho.0,
        outcome_chirho.output_chirho.len(),
        outcome_chirho.fuel_used_chirho
    );
    let trace_hash_chirho = cas_chirho::add_chirho(root_chirho, trace_text_chirho.as_bytes())?;

    let result_chirho = RunResultChirho {
        run_chirho: run_hash_chirho,
        outputs_chirho,
        effects_chirho: vec![],
        fuel_used_chirho: outcome_chirho.fuel_used_chirho,
        trace_chirho: trace_hash_chirho,
        status_chirho: RunStatusChirho::OkChirho,
        parents_chirho: parents_chirho.to_vec(),
    };
    store_result_chirho(root_chirho, &result_chirho)?;
    Ok((result_chirho, false))
}

fn usize_node_limit_chirho(limit_chirho: u64) -> Result<usize> {
    usize::try_from(limit_chirho).context("NodeDefChirho limit does not fit usize")
}

/// Run an **effect node** (a `NodeDefChirho` with capabilities), using the run cache + the
/// effect log. The input bytes are the effect's request; the effect's response is the node's
/// output. The run-key hash doubles as the idempotency key; non-volatile effects replay by it,
/// while live reads re-execute and overwrite that logged slot with the current response.
pub fn run_effect_node_cached_chirho(
    root_chirho: &Path,
    node_def_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
    input_hash_chirho: &HashChirho,
    parents_chirho: &[HashChirho],
) -> Result<(RunResultChirho, bool)> {
    run_effect_node_cached_with_context_chirho(
        root_chirho,
        node_def_chirho,
        node_hash_chirho,
        input_hash_chirho,
        parents_chirho,
        None,
    )
}

pub fn run_effect_node_cached_with_context_chirho(
    root_chirho: &Path,
    node_def_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
    input_hash_chirho: &HashChirho,
    parents_chirho: &[HashChirho],
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<(RunResultChirho, bool)> {
    let mut resolver_chirho = dag_private_value_chirho::PrivateDagValueResolverChirho::default();
    run_effect_node_cached_with_context_and_value_storage_chirho(
        root_chirho,
        node_def_chirho,
        node_hash_chirho,
        input_hash_chirho,
        parents_chirho,
        request_context_chirho,
        CachedValueStorageChirho {
            resolver_chirho: &mut resolver_chirho,
            output_storage_chirho:
                &dag_private_value_chirho::ValueStoragePolicyChirho::PublicCasChirho,
            attribution_source_chirho:
                dag_private_value_chirho::RunAttributionSourceChirho::new_chirho(
                    request_context_chirho,
                    None,
                ),
        },
    )
}

/// Runs one verified effect node; descriptor-v2 admission precedes cache lookup and billing.
/// Workflow: `spec-chirho/workflows-chirho/undo-chirho/static-undo-plan-design-chirho.md` 4.2.1.
pub fn run_effect_node_cached_with_context_and_value_storage_chirho(
    root_chirho: &Path,
    node_def_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
    input_hash_chirho: &HashChirho,
    parents_chirho: &[HashChirho],
    request_context_chirho: Option<&RequestContextChirho>,
    storage_chirho: CachedValueStorageChirho<'_>,
) -> Result<(RunResultChirho, bool)> {
    run_effect_node_cached_spine_chirho(
        root_chirho,
        node_def_chirho,
        node_hash_chirho,
        input_hash_chirho,
        parents_chirho,
        request_context_chirho,
        EffectNodeRuntimeOptionsChirho {
            storage_chirho,
            postgres_reversible_chirho: None,
            llm_served_chirho: None,
            projection_read_chirho: None,
        },
    )
}

/// Explicit CF4 published-projection composition seam. The caller must thread an injected port;
/// passing `None` preserves Brick 2's typed Query refusal. Composed Query results are volatile,
/// non-cached, and carry zero `EffectChirho` rows by construction.
pub struct PublishedProjectionReadRuntimeChirho<'runtime_chirho> {
    pub request_context_chirho: Option<&'runtime_chirho RequestContextChirho>,
    pub projection_read_chirho: Option<
        &'runtime_chirho dyn effect_chirho::projection_read_chirho::PublishedProjectionReadPortChirho,
    >,
}

/// Cache-spine inputs that vary with one execution rather than with the immutable node.
pub struct EffectNodeExecutionRuntimeChirho<'storage_chirho, 'runtime_chirho> {
    pub request_context_chirho: Option<&'runtime_chirho RequestContextChirho>,
    pub storage_chirho: CachedValueStorageChirho<'storage_chirho>,
    pub runtime_ports_chirho: effect_chirho::DagEffectRuntimePortsChirho<'runtime_chirho>,
}

pub fn run_effect_node_cached_with_context_value_storage_and_projection_read_chirho(
    root_chirho: &Path,
    node_def_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
    input_hash_chirho: &HashChirho,
    parents_chirho: &[HashChirho],
    storage_chirho: CachedValueStorageChirho<'_>,
    runtime_chirho: PublishedProjectionReadRuntimeChirho<'_>,
) -> Result<(RunResultChirho, bool)> {
    let PublishedProjectionReadRuntimeChirho {
        request_context_chirho,
        projection_read_chirho,
    } = runtime_chirho;
    run_effect_node_cached_with_context_value_storage_and_runtime_ports_chirho(
        root_chirho,
        node_def_chirho,
        node_hash_chirho,
        input_hash_chirho,
        parents_chirho,
        EffectNodeExecutionRuntimeChirho {
            request_context_chirho,
            storage_chirho,
            runtime_ports_chirho: effect_chirho::DagEffectRuntimePortsChirho {
                projection_read_chirho,
                postgres_reversible_chirho: None,
                llm_served_chirho: None,
                private_attribution_chirho: None,
            },
        },
    )
}

/// One shared effect-node composition seam for projection reads and Descriptor-D. DAG/run-intent
/// callers thread this exact bundle through fresh, private, resume, and completed-replay modes.
pub fn run_effect_node_cached_with_context_value_storage_and_runtime_ports_chirho(
    root_chirho: &Path,
    node_def_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
    input_hash_chirho: &HashChirho,
    parents_chirho: &[HashChirho],
    runtime_chirho: EffectNodeExecutionRuntimeChirho<'_, '_>,
) -> Result<(RunResultChirho, bool)> {
    let EffectNodeExecutionRuntimeChirho {
        request_context_chirho,
        storage_chirho,
        runtime_ports_chirho,
    } = runtime_chirho;
    // The storage's attribution source was built from this same request and these same ports, so
    // the ports' declared attribution is already in it.
    let effect_chirho::DagEffectRuntimePortsChirho {
        projection_read_chirho,
        postgres_reversible_chirho,
        llm_served_chirho,
        private_attribution_chirho: _,
    } = runtime_ports_chirho;
    run_effect_node_cached_spine_chirho(
        root_chirho,
        node_def_chirho,
        node_hash_chirho,
        input_hash_chirho,
        parents_chirho,
        request_context_chirho,
        EffectNodeRuntimeOptionsChirho {
            storage_chirho,
            postgres_reversible_chirho,
            llm_served_chirho,
            projection_read_chirho,
        },
    )
}

/// Explicit Descriptor-D composition seam. Existing serve and DAG paths do not call this helper,
/// so a registered card remains fail-closed until the reviewed root injects its provider.
pub fn run_effect_node_cached_with_context_and_postgres_runtime_chirho(
    root_chirho: &Path,
    node_def_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
    input_hash_chirho: &HashChirho,
    parents_chirho: &[HashChirho],
    request_context_chirho: Option<&RequestContextChirho>,
    postgres_reversible_chirho: &mut dyn effect_chirho::postgres_reversible_chirho::PostgresReversibleRuntimePortChirho,
) -> Result<(RunResultChirho, bool)> {
    let mut resolver_chirho = dag_private_value_chirho::PrivateDagValueResolverChirho::default();
    run_effect_node_cached_with_context_value_storage_and_runtime_ports_chirho(
        root_chirho,
        node_def_chirho,
        node_hash_chirho,
        input_hash_chirho,
        parents_chirho,
        EffectNodeExecutionRuntimeChirho {
            request_context_chirho,
            storage_chirho: CachedValueStorageChirho {
                resolver_chirho: &mut resolver_chirho,
                output_storage_chirho:
                    &dag_private_value_chirho::ValueStoragePolicyChirho::PublicCasChirho,
                attribution_source_chirho:
                    dag_private_value_chirho::RunAttributionSourceChirho::new_chirho(
                        request_context_chirho,
                        None,
                    ),
            },
            runtime_ports_chirho: effect_chirho::DagEffectRuntimePortsChirho {
                postgres_reversible_chirho: Some(postgres_reversible_chirho),
                llm_served_chirho: None,
                projection_read_chirho: None,
                private_attribution_chirho: None,
            },
        },
    )
}

struct EffectNodeRuntimeOptionsChirho<'storage_chirho, 'runtime_chirho> {
    storage_chirho: CachedValueStorageChirho<'storage_chirho>,
    postgres_reversible_chirho: Option<
        &'runtime_chirho mut dyn effect_chirho::postgres_reversible_chirho::PostgresReversibleRuntimePortChirho,
    >,
    llm_served_chirho: Option<
        &'runtime_chirho mut dyn effect_chirho::llm_served_chirho::LlmServedRuntimePortChirho,
    >,
    projection_read_chirho: Option<
        &'runtime_chirho dyn effect_chirho::projection_read_chirho::PublishedProjectionReadPortChirho,
    >,
}

fn run_effect_node_cached_spine_chirho(
    root_chirho: &Path,
    node_def_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
    input_hash_chirho: &HashChirho,
    parents_chirho: &[HashChirho],
    request_context_chirho: Option<&RequestContextChirho>,
    options_chirho: EffectNodeRuntimeOptionsChirho<'_, '_>,
) -> Result<(RunResultChirho, bool)> {
    let EffectNodeRuntimeOptionsChirho {
        mut storage_chirho,
        postgres_reversible_chirho,
        llm_served_chirho,
        projection_read_chirho,
    } = options_chirho;
    let effective_def_chirho = contextual_node_def_chirho(node_def_chirho, request_context_chirho);
    let capability_chirho = executable_effect_capability_chirho(&effective_def_chirho)?;
    if let CapabilityChirho::InvokeChirho {
        node_chirho: target_node_chirho,
    } = &capability_chirho
    {
        if target_node_chirho == node_hash_chirho {
            bail!("InvokeChirho node cannot invoke itself");
        }
    }
    if matches!(capability_chirho, CapabilityChirho::PaidEffectChirho { .. })
        && request_context_chirho.is_none()
    {
        bail!("charge-bearing PaidEffectChirho requires verified RequestContextChirho");
    }
    enforce_identity_for_paid_effect_chirho(&effective_def_chirho, &capability_chirho)?;
    let admission_chirho = blessed_chirho::admit_verified_node_effect_chirho(
        node_def_chirho,
        node_hash_chirho,
        &capability_chirho,
    )?;
    let may_reuse_generic_effect_result_chirho =
        admission_chirho.may_reuse_generic_effect_result_chirho()?;
    let verified_asset_input_chirho = if admission_chirho.requires_asset_op_request_chirho() {
        let input_bytes_chirho = storage_chirho
            .resolver_chirho
            .read_value_bytes_chirho(root_chirho, input_hash_chirho)?;
        admission_chirho.authorize_request_chirho(&input_bytes_chirho)?;
        Some(input_bytes_chirho)
    } else {
        None
    };
    let volatile_chirho = effect_chirho::is_volatile_chirho(&capability_chirho);
    let key_chirho =
        build_bytes_run_key_chirho(&effective_def_chirho, node_hash_chirho, input_hash_chirho)?;
    let run_hash_chirho = store_chirho::hash_object_chirho(&key_chirho)?;
    store_run_key_chirho(root_chirho, &run_hash_chirho, &key_chirho)?;

    // A volatile effect (live read) always re-executes; others may be served from the cache.
    if !volatile_chirho && may_reuse_generic_effect_result_chirho {
        if let Some(cached_chirho) = load_sealed_result_chirho(root_chirho, &run_hash_chirho)? {
            let cached_chirho = cached_effect_with_current_parents_chirho(
                root_chirho,
                cached_chirho,
                parents_chirho,
                &capability_chirho,
            )?;
            bill_cached_paid_effect_chirho(
                root_chirho,
                &capability_chirho,
                &run_hash_chirho,
                request_context_chirho,
            )?;
            bill_cached_invoked_paid_effects_chirho(
                root_chirho,
                &cached_chirho,
                &capability_chirho,
                request_context_chirho,
            )?;
            if bind_cached_outputs_chirho(root_chirho, &cached_chirho, &mut storage_chirho)? {
                return Ok((cached_chirho, true));
            }
        }
    }

    let input_bytes_chirho = match verified_asset_input_chirho {
        Some(input_bytes_chirho) => input_bytes_chirho,
        None => storage_chirho
            .resolver_chirho
            .read_value_bytes_chirho(root_chirho, input_hash_chirho)?,
    };
    if matches!(capability_chirho, CapabilityChirho::QueryChirho { .. }) {
        let response_bytes_chirho =
            effect_chirho::projection_read_chirho::run_published_projection_read_chirho(
                projection_read_chirho,
                &capability_chirho,
                &input_bytes_chirho,
                request_context_chirho,
            )?;
        let output_port_chirho = output_port_chirho(node_def_chirho);
        let response_hash_chirho = dag_private_value_chirho::store_dag_value_with_policy_chirho(
            root_chirho,
            &response_bytes_chirho,
            storage_chirho.output_storage_chirho,
            dag_private_value_chirho::PrivateDagValueContextChirho {
                run_chirho: Some(run_hash_chirho.clone()),
                node_chirho: Some(node_hash_chirho.clone()),
                port_chirho: Some(output_port_chirho.clone()),
                ..Default::default()
            },
            Some(storage_chirho.resolver_chirho),
            &storage_chirho.attribution_source_chirho,
        )?;
        let mut outputs_chirho = BTreeMap::new();
        outputs_chirho.insert(output_port_chirho, response_hash_chirho);
        let trace_text_chirho = format!(
            "published-projection-read node={} in={} outcome_bytes={}",
            effective_def_chirho.name_chirho,
            input_hash_chirho.0,
            response_bytes_chirho.len()
        );
        let trace_chirho = cas_chirho::add_chirho(root_chirho, trace_text_chirho.as_bytes())?;
        return Ok((
            RunResultChirho {
                run_chirho: run_hash_chirho,
                outputs_chirho,
                effects_chirho: vec![],
                fuel_used_chirho: 0,
                trace_chirho,
                status_chirho: RunStatusChirho::OkChirho,
                parents_chirho: parents_chirho.to_vec(),
            },
            false,
        ));
    }
    let input_hash_for_effect_chirho = if storage_chirho
        .resolver_chirho
        .domain_for_hash_chirho(input_hash_chirho)?
        .is_some()
    {
        Some(input_hash_chirho.clone())
    } else {
        None
    };

    let eff_chirho = effect_chirho::run_admitted_effect_with_context_and_value_storage_chirho(
        root_chirho,
        0,
        run_hash_chirho.clone(),
        capability_chirho.clone(),
        &input_bytes_chirho,
        effect_chirho::AdmittedEffectRunOptionsChirho {
            storage_chirho: effect_chirho::EffectValueStorageChirho {
                request_hash_chirho: input_hash_for_effect_chirho,
                response_storage_chirho: Some(storage_chirho.output_storage_chirho.clone()),
                response_context_chirho: dag_private_value_chirho::PrivateDagValueContextChirho {
                    run_chirho: Some(run_hash_chirho.clone()),
                    node_chirho: Some(node_hash_chirho.clone()),
                    port_chirho: Some(output_port_chirho(node_def_chirho)),
                    ..Default::default()
                },
            },
            request_context_chirho,
            attribution_source_chirho: storage_chirho.attribution_source_chirho,
            admission_chirho: &admission_chirho,
            postgres_reversible_chirho,
            llm_served_chirho,
        },
    )?;
    let effect_response_hash_chirho = eff_chirho
        .response_chirho
        .clone()
        .ok_or_else(|| anyhow!("effect produced no response"))
        .map_err(|error_chirho| {
            crate::dag_chirho::refusal_chirho::wrap_dag_execution_stage_chirho(
                crate::dag_chirho::refusal_chirho::DagExecutionRefusalIdentityChirho::DagEffectResultAccountingRefusedChirho,
                error_chirho,
            )
        })?;
    let (response_hash_chirho, invoked_parent_chirho) = effect_output_and_invoked_parent_chirho(
        root_chirho,
        &capability_chirho,
        &effect_response_hash_chirho,
    )
    .map_err(|error_chirho| {
        crate::dag_chirho::refusal_chirho::wrap_dag_execution_stage_chirho(
            crate::dag_chirho::refusal_chirho::DagExecutionRefusalIdentityChirho::DagEffectResultAccountingRefusedChirho,
            error_chirho,
        )
    })?;
    // Neither sealed store response — the value a WRITE sealed, nor the plaintext a live READ
    // unsealed — ever rests in public CAS, so the run must be able to resolve it privately or a
    // downstream node would look for bytes that are deliberately gone. The precedence here mirrors
    // the arms' exactly: an edge-declared private subject wins, otherwise the row's own seal
    // subject — taken from the one shared `store_seal_response_subject_chirho`, so the subject
    // sealed under and the subject resolved by cannot drift apart.
    let effective_private_subject_chirho = match storage_chirho
        .output_storage_chirho
        .private_domain_chirho()
    {
        Some((edge_subject_chirho, edge_owner_chirho)) => {
            Some((edge_subject_chirho.to_string(), edge_owner_chirho))
        }
        None => effect_chirho::store_seal_response_subject_chirho(
            root_chirho,
            &capability_chirho,
            &input_bytes_chirho,
            request_context_chirho,
        )
        .map_err(|error_chirho| {
            crate::dag_chirho::refusal_chirho::wrap_dag_execution_stage_chirho(
                crate::dag_chirho::refusal_chirho::DagExecutionRefusalIdentityChirho::DagEffectResultAccountingRefusedChirho,
                error_chirho,
            )
        })?,
    };
    if let Some((subject_chirho, owner_chirho)) = effective_private_subject_chirho {
        storage_chirho.resolver_chirho.insert_private_hash_chirho(
            &subject_chirho,
            owner_chirho,
            &response_hash_chirho,
        );
    }

    let mut outputs_chirho = BTreeMap::new();
    outputs_chirho.insert(output_port_chirho(node_def_chirho), response_hash_chirho);

    let app_context_label_chirho = request_context_chirho
        .map(|context_chirho| {
            format!(
                " app={} owner={}",
                context_chirho.app_chirho, context_chirho.owner_principal_chirho
            )
        })
        .unwrap_or_default();
    let trace_text_chirho = format!(
        "effect node={} cap={:?} auth_user={}{} in={}",
        effective_def_chirho.name_chirho,
        eff_chirho.capability_chirho,
        authorizing_user_chirho(&effective_def_chirho).unwrap_or("none"),
        app_context_label_chirho,
        input_hash_chirho.0
    );
    let trace_hash_chirho = cas_chirho::add_chirho(root_chirho, trace_text_chirho.as_bytes())
        .map_err(|error_chirho| {
            crate::dag_chirho::refusal_chirho::wrap_dag_execution_stage_chirho(
                crate::dag_chirho::refusal_chirho::DagExecutionRefusalIdentityChirho::DagEffectResultAccountingRefusedChirho,
                error_chirho,
            )
        })?;

    let result_chirho = RunResultChirho {
        run_chirho: run_hash_chirho,
        outputs_chirho,
        effects_chirho: vec![eff_chirho],
        fuel_used_chirho: 0,
        trace_chirho: trace_hash_chirho,
        status_chirho: RunStatusChirho::OkChirho,
        parents_chirho: parents_with_invoked_parent_chirho(parents_chirho, invoked_parent_chirho),
    };
    // Volatile effects are never cached, so a live read is always fresh next run.
    if !volatile_chirho && may_reuse_generic_effect_result_chirho {
        store_result_chirho(root_chirho, &result_chirho).map_err(|error_chirho| {
            crate::dag_chirho::refusal_chirho::wrap_dag_execution_stage_chirho(
                crate::dag_chirho::refusal_chirho::DagExecutionRefusalIdentityChirho::DagEffectResultAccountingRefusedChirho,
                error_chirho,
            )
        })?;
    }
    Ok((result_chirho, false))
}

pub(crate) fn effect_output_and_invoked_parent_chirho(
    root_chirho: &Path,
    capability_chirho: &CapabilityChirho,
    effect_response_hash_chirho: &HashChirho,
) -> Result<(HashChirho, Option<HashChirho>)> {
    if let CapabilityChirho::InvokeChirho { .. } = capability_chirho {
        let response_chirho =
            invoke_response_from_effect_response_chirho(root_chirho, effect_response_hash_chirho)?;
        Ok((
            response_chirho.payload_hash_chirho,
            Some(response_chirho.target_run_chirho),
        ))
    } else {
        Ok((effect_response_hash_chirho.clone(), None))
    }
}

pub(crate) fn invoke_response_from_effect_response_chirho(
    root_chirho: &Path,
    effect_response_hash_chirho: &HashChirho,
) -> Result<effect_chirho::InvokeResponseChirho> {
    let response_bytes_chirho = cas_chirho::get_chirho(root_chirho, effect_response_hash_chirho)
        .with_context(|| {
            format!(
                "InvokeChirho response {} not in store",
                effect_response_hash_chirho.0
            )
        })?;
    serde_json::from_slice(&response_bytes_chirho).context("decode InvokeResponseChirho")
}

fn cached_effect_with_current_parents_chirho(
    root_chirho: &Path,
    mut cached_chirho: RunResultChirho,
    parents_chirho: &[HashChirho],
    capability_chirho: &CapabilityChirho,
) -> Result<RunResultChirho> {
    let invoked_parent_chirho =
        cached_invoked_parent_chirho(root_chirho, &cached_chirho, capability_chirho)?;
    let expected_parents_chirho =
        parents_with_invoked_parent_chirho(parents_chirho, invoked_parent_chirho);
    if cached_chirho.parents_chirho != expected_parents_chirho {
        cached_chirho.parents_chirho = expected_parents_chirho;
        store_result_chirho(root_chirho, &cached_chirho)?;
    }
    Ok(cached_chirho)
}

fn cached_invoked_parent_chirho(
    root_chirho: &Path,
    cached_chirho: &RunResultChirho,
    capability_chirho: &CapabilityChirho,
) -> Result<Option<HashChirho>> {
    Ok(
        cached_invoke_response_chirho(root_chirho, cached_chirho, capability_chirho)?
            .map(|response_chirho| response_chirho.target_run_chirho),
    )
}

pub(crate) fn cached_invoke_response_chirho(
    root_chirho: &Path,
    cached_chirho: &RunResultChirho,
    capability_chirho: &CapabilityChirho,
) -> Result<Option<effect_chirho::InvokeResponseChirho>> {
    if !matches!(capability_chirho, CapabilityChirho::InvokeChirho { .. }) {
        return Ok(None);
    }
    let effect_chirho = cached_chirho
        .effects_chirho
        .first()
        .ok_or_else(|| anyhow!("cached InvokeChirho run has no effect record"))?;
    let effect_response_hash_chirho = effect_chirho
        .response_chirho
        .as_ref()
        .ok_or_else(|| anyhow!("cached InvokeChirho effect has no response"))?;
    Ok(Some(invoke_response_from_effect_response_chirho(
        root_chirho,
        effect_response_hash_chirho,
    )?))
}

pub(crate) fn parents_with_invoked_parent_chirho(
    parents_chirho: &[HashChirho],
    invoked_parent_chirho: Option<HashChirho>,
) -> Vec<HashChirho> {
    let mut result_parents_chirho = parents_chirho.to_vec();
    if let Some(invoked_parent_chirho) = invoked_parent_chirho {
        if !result_parents_chirho.contains(&invoked_parent_chirho) {
            result_parents_chirho.push(invoked_parent_chirho);
        }
    }
    result_parents_chirho
}

pub(crate) fn bill_cached_invoked_paid_effects_chirho(
    root_chirho: &Path,
    cached_chirho: &RunResultChirho,
    capability_chirho: &CapabilityChirho,
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<()> {
    if effect_chirho::run_intent_cached_billing_suppressed_chirho() {
        return Ok(());
    }
    let Some(response_chirho) =
        cached_invoke_response_chirho(root_chirho, cached_chirho, capability_chirho)?
    else {
        return Ok(());
    };
    bill_cached_paid_effects_for_run_chirho(
        root_chirho,
        &response_chirho.target_run_chirho,
        request_context_chirho,
        &mut BTreeSet::new(),
    )
}
fn bill_cached_paid_effects_for_run_chirho(
    root_chirho: &Path,
    run_hash_chirho: &HashChirho,
    request_context_chirho: Option<&RequestContextChirho>,
    seen_chirho: &mut BTreeSet<HashChirho>,
) -> Result<()> {
    if !seen_chirho.insert(run_hash_chirho.clone()) {
        return Ok(());
    }
    let result_chirho = load_sealed_result_chirho(root_chirho, run_hash_chirho)?
        .ok_or_else(|| anyhow!("invoked target run {} not in store", run_hash_chirho.0))?;
    let cached_run_key_chirho =
        load_run_key_chirho(root_chirho, run_hash_chirho)?.ok_or_else(|| {
            anyhow!(
                "invoked target run {} has no RunKeyChirho",
                run_hash_chirho.0
            )
        })?;
    if store_chirho::hash_object_chirho(&cached_run_key_chirho)? != *run_hash_chirho {
        bail!("cached invoked target RunKeyChirho does not match its run identity");
    }
    let cached_node_def_chirho: NodeDefChirho =
        store_chirho::get_object_chirho(root_chirho, &cached_run_key_chirho.node_chirho)
            .context("load cached invoked target NodeDefChirho for effect admission")?;
    for effect_chirho in &result_chirho.effects_chirho {
        let admission_chirho = blessed_chirho::admit_verified_node_effect_chirho(
            &cached_node_def_chirho,
            &cached_run_key_chirho.node_chirho,
            &effect_chirho.capability_chirho,
        )?;
        if admission_chirho.requires_asset_op_request_chirho() {
            let request_bytes_chirho =
                cas_chirho::get_chirho(root_chirho, &effect_chirho.request_chirho).context(
                    "cached AssetOp request stone is unavailable for pre-billing verification",
                )?;
            admission_chirho.authorize_request_chirho(&request_bytes_chirho)?;
        }
        match &effect_chirho.capability_chirho {
            CapabilityChirho::PaidEffectChirho { .. } => match request_context_chirho {
                Some(context_chirho) => bill_cached_paid_effect_chirho(
                    root_chirho,
                    &effect_chirho.capability_chirho,
                    &result_chirho.run_chirho,
                    Some(context_chirho),
                )?,
                None => bail!(
                    "cached charge-bearing PaidEffectChirho requires verified RequestContextChirho"
                ),
            },
            CapabilityChirho::InvokeChirho { .. } => {
                let response_chirho = invoke_response_from_effect_response_chirho(
                    root_chirho,
                    effect_chirho.response_chirho.as_ref().ok_or_else(|| {
                        anyhow!("cached nested InvokeChirho effect has no response")
                    })?,
                )?;
                bill_cached_paid_effects_for_run_chirho(
                    root_chirho,
                    &response_chirho.target_run_chirho,
                    request_context_chirho,
                    seen_chirho,
                )?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn cached_with_current_parents_chirho(
    root_chirho: &Path,
    mut cached_chirho: RunResultChirho,
    parents_chirho: &[HashChirho],
) -> Result<RunResultChirho> {
    if cached_chirho.parents_chirho != parents_chirho {
        cached_chirho.parents_chirho = parents_chirho.to_vec();
        store_result_chirho(root_chirho, &cached_chirho)?;
    }
    Ok(cached_chirho)
}

fn executable_effect_capability_chirho(
    node_def_chirho: &NodeDefChirho,
) -> Result<CapabilityChirho> {
    node_def_chirho
        .capabilities_chirho
        .iter()
        .find(|capability_chirho| !is_context_capability_chirho(capability_chirho))
        .cloned()
        .ok_or_else(|| {
            anyhow!(
                "effect node '{}' declares no executable effect capability",
                node_def_chirho.name_chirho
            )
        })
}

fn is_context_capability_chirho(capability_chirho: &CapabilityChirho) -> bool {
    matches!(
        capability_chirho,
        CapabilityChirho::UserIdentityChirho { .. }
            | CapabilityChirho::AppContextChirho { .. }
            | CapabilityChirho::SecretRefChirho { .. }
    )
}

pub(crate) fn bill_cached_paid_effect_chirho(
    _root_chirho: &Path,
    capability_chirho: &CapabilityChirho,
    _run_hash_chirho: &HashChirho,
    _request_context_chirho: Option<&RequestContextChirho>,
) -> Result<()> {
    if let CapabilityChirho::PaidEffectChirho {
        effect_chirho: effect_name_chirho,
        ..
    } = capability_chirho
    {
        return Err(anyhow::Error::new(
            effect_chirho::LegacyMoneyRoadRefusedChirho::new_chirho(
                effect_chirho::LegacyMoneyRoadChirho::CachedPaidEffectChirho,
                effect_name_chirho,
            ),
        ));
    }
    Ok(())
}

fn contextual_node_def_chirho(
    node_def_chirho: &NodeDefChirho,
    request_context_chirho: Option<&RequestContextChirho>,
) -> NodeDefChirho {
    let Some(context_chirho) = request_context_chirho else {
        return node_def_chirho.clone();
    };
    let mut effective_chirho = node_def_chirho.clone();
    effective_chirho.capabilities_chirho = node_def_chirho
        .capabilities_chirho
        .iter()
        .filter_map(|capability_chirho| match capability_chirho {
            CapabilityChirho::PaidEffectChirho { effect_chirho, .. } => {
                Some(CapabilityChirho::PaidEffectChirho {
                    effect_chirho: effect_chirho.clone(),
                    caller_chirho: context_chirho.user_principal_chirho.clone(),
                })
            }
            CapabilityChirho::QueryChirho {
                prefix_chirho,
                max_rows_chirho,
                ..
            } => Some(CapabilityChirho::QueryChirho {
                prefix_chirho: prefix_chirho.clone(),
                caller_chirho: context_chirho.user_principal_chirho.clone(),
                max_rows_chirho: *max_rows_chirho,
            }),
            CapabilityChirho::UserIdentityChirho { .. }
            | CapabilityChirho::AppContextChirho { .. } => None,
            other_chirho => Some(other_chirho.clone()),
        })
        .collect();
    effective_chirho
        .capabilities_chirho
        .push(CapabilityChirho::UserIdentityChirho {
            principal_chirho: context_chirho.user_principal_chirho.clone(),
            client_id_chirho: context_chirho.client_id_chirho.clone(),
            token_hash_chirho: context_chirho.token_hash_chirho.clone(),
        });
    effective_chirho
        .capabilities_chirho
        .push(CapabilityChirho::AppContextChirho {
            app_chirho: context_chirho.app_chirho.clone(),
            owner_principal_chirho: context_chirho.owner_principal_chirho.clone(),
            price_book_chirho: context_chirho.price_book_chirho.clone(),
            billing_policy_chirho: context_chirho.billing_policy_chirho.clone(),
        });
    effective_chirho
}

fn enforce_identity_for_paid_effect_chirho(
    node_def_chirho: &NodeDefChirho,
    capability_chirho: &CapabilityChirho,
) -> Result<()> {
    let caller_chirho = match capability_chirho {
        CapabilityChirho::PaidEffectChirho { caller_chirho, .. }
        | CapabilityChirho::QueryChirho { caller_chirho, .. } => caller_chirho,
        _ => return Ok(()),
    };
    {
        let authorized_chirho =
            node_def_chirho
                .capabilities_chirho
                .iter()
                .any(|capability_chirho| {
                    matches!(
                        capability_chirho,
                        CapabilityChirho::UserIdentityChirho { principal_chirho, .. }
                            if principal_chirho == caller_chirho
                    )
                });
        if !authorized_chirho {
            bail!(
                "effect '{}' requires matching UserIdentityChirho for caller '{}'",
                node_def_chirho.name_chirho,
                caller_chirho
            );
        }
    }
    Ok(())
}

fn authorizing_user_chirho(node_def_chirho: &NodeDefChirho) -> Option<&str> {
    node_def_chirho
        .capabilities_chirho
        .iter()
        .find_map(|capability_chirho| {
            if let CapabilityChirho::UserIdentityChirho {
                principal_chirho, ..
            } = capability_chirho
            {
                Some(principal_chirho.as_str())
            } else {
                None
            }
        })
}

#[path = "cache_chirho/phi_chirho.rs"]
mod phi_chirho;
pub(crate) use phi_chirho::{phi_live_input_chirho, run_phi_node_cached_chirho};

#[cfg(test)]
#[path = "cache_chirho/tests_chirho.rs"]
mod tests_chirho;

#[cfg(test)]
#[path = "cache_chirho/run_key_tests_chirho.rs"]
mod run_key_tests_chirho;
