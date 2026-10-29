// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Verify — recompute content hashes + check effect signatures for runs and live-effect logs.
//!
//! Three tamper-evidence checks, walked over the whole provenance chain (via `audit_chirho`):
//!   1. every run result is bound to the queried run id and its stored `RunKeyChirho`;
//!   2. the `RunKeyChirho` node/input/code/schema dependencies are present and re-hash;
//!   3. every content-addressed object (outputs, trace, effect request/response) is re-hashed
//!      and must equal its stored address — any change to the bytes changes the hash;
//!   4. every `EffectChirho` signature must verify against the instance ed25519 key (M1.4).
//!
//! The volatile live-read log is verified separately because those effects refresh their latest
//! idempotency slot instead of being anchored only by persisted `RunResultChirho` records.
//! `run-cache-verify` scans the whole local cache for the same run-result/run-key binding.

use crate::model_chirho::{HashChirho, NodeDefChirho, RunKeyChirho, RunResultChirho};
use crate::{
    audit_chirho, cache_chirho, cas_chirho, dag_private_value_chirho, effect_chirho,
    native_worker_chirho, store_chirho,
};
use anyhow::{bail, Context, Result};
use std::collections::BTreeSet;
use std::path::Path;

pub const RUN_CACHE_VERIFY_REPORT_SCHEMA_CHIRHO: &str = "run-cache-verify-report-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RunCacheResultMismatchChirho {
    pub file_run_chirho: String,
    pub declared_run_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RunCacheRunKeyMismatchChirho {
    pub file_run_chirho: String,
    pub computed_run_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RunCacheComponentFailureChirho {
    pub run_chirho: String,
    pub error_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RunCacheSealFailureChirho {
    pub run_chirho: String,
    pub error_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RunCacheVerifyReportChirho {
    pub schema_chirho: String,
    pub runs_chirho: usize,
    pub runkeys_chirho: usize,
    pub runseals_chirho: usize,
    pub missing_runkeys_chirho: Vec<String>,
    pub result_run_mismatches_chirho: Vec<RunCacheResultMismatchChirho>,
    pub run_result_seal_failures_chirho: Vec<RunCacheSealFailureChirho>,
    pub runkey_hash_mismatches_chirho: Vec<RunCacheRunKeyMismatchChirho>,
    pub runkey_component_failures_chirho: Vec<RunCacheComponentFailureChirho>,
    pub orphan_runkeys_chirho: Vec<String>,
    pub orphan_runseals_chirho: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolatileEffectVerifyReportChirho {
    pub records_chirho: usize,
    pub objects_chirho: usize,
}

/// Verify a run and its whole provenance chain. Returns the number of cache/CAS records checked.
/// Errors on the first tampered object or bad signature.
pub fn verify_chirho(root_chirho: &Path, run_hash_chirho: &HashChirho) -> Result<usize> {
    let chain_chirho = audit_chirho::audit_chirho(root_chirho, run_hash_chirho)?;
    let mut checked_chirho = 0usize;
    for entry_chirho in &chain_chirho {
        if let Some(result_chirho) = &entry_chirho.result_chirho {
            checked_chirho += verify_run_cache_binding_chirho(
                root_chirho,
                &entry_chirho.run_chirho,
                result_chirho,
            )?;
            checked_chirho += verify_run_objects_chirho(root_chirho, result_chirho)?;
        }
    }
    Ok(checked_chirho)
}

pub fn inspect_run_cache_chirho(root_chirho: &Path) -> Result<RunCacheVerifyReportChirho> {
    let run_ids_chirho = cache_dir_file_names_chirho(root_chirho, "runs-chirho")?;
    let runkey_ids_chirho = cache_dir_file_names_chirho(root_chirho, "runkeys-chirho")?;
    let runseal_ids_chirho = cache_dir_file_names_chirho(root_chirho, "runseals-chirho")?;

    let mut report_chirho = RunCacheVerifyReportChirho {
        schema_chirho: RUN_CACHE_VERIFY_REPORT_SCHEMA_CHIRHO.to_string(),
        runs_chirho: run_ids_chirho.len(),
        runkeys_chirho: runkey_ids_chirho.len(),
        runseals_chirho: runseal_ids_chirho.len(),
        missing_runkeys_chirho: Vec::new(),
        result_run_mismatches_chirho: Vec::new(),
        run_result_seal_failures_chirho: Vec::new(),
        runkey_hash_mismatches_chirho: Vec::new(),
        runkey_component_failures_chirho: Vec::new(),
        orphan_runkeys_chirho: runkey_ids_chirho
            .difference(&run_ids_chirho)
            .cloned()
            .collect(),
        orphan_runseals_chirho: runseal_ids_chirho
            .difference(&run_ids_chirho)
            .cloned()
            .collect(),
    };

    for run_id_chirho in &run_ids_chirho {
        let expected_run_chirho = HashChirho(run_id_chirho.clone());
        let Some(result_chirho) =
            cache_chirho::load_result_chirho(root_chirho, &expected_run_chirho)?
        else {
            bail!("run result cache file disappeared while scanning {run_id_chirho}");
        };
        if result_chirho.run_chirho != expected_run_chirho {
            report_chirho
                .result_run_mismatches_chirho
                .push(RunCacheResultMismatchChirho {
                    file_run_chirho: run_id_chirho.clone(),
                    declared_run_chirho: result_chirho.run_chirho.0.clone(),
                });
        }
        if let Err(error_chirho) = cache_chirho::verify_run_result_seal_chirho(
            root_chirho,
            &expected_run_chirho,
            &result_chirho,
        ) {
            report_chirho
                .run_result_seal_failures_chirho
                .push(RunCacheSealFailureChirho {
                    run_chirho: run_id_chirho.clone(),
                    error_chirho: error_chirho.to_string(),
                });
        }
        if !runkey_ids_chirho.contains(run_id_chirho) {
            report_chirho
                .missing_runkeys_chirho
                .push(run_id_chirho.clone());
        }
    }

    for runkey_id_chirho in &runkey_ids_chirho {
        let expected_run_chirho = HashChirho(runkey_id_chirho.clone());
        let Some(run_key_chirho) =
            cache_chirho::load_run_key_chirho(root_chirho, &expected_run_chirho)?
        else {
            bail!("RunKeyChirho sidecar disappeared while scanning {runkey_id_chirho}");
        };
        let recomputed_chirho = store_chirho::hash_object_chirho(&run_key_chirho)?;
        if recomputed_chirho != expected_run_chirho {
            report_chirho
                .runkey_hash_mismatches_chirho
                .push(RunCacheRunKeyMismatchChirho {
                    file_run_chirho: runkey_id_chirho.clone(),
                    computed_run_chirho: recomputed_chirho.0,
                });
        }
        if let Err(error_chirho) =
            verify_run_key_components_chirho(root_chirho, &expected_run_chirho, &run_key_chirho)
        {
            report_chirho
                .runkey_component_failures_chirho
                .push(RunCacheComponentFailureChirho {
                    run_chirho: runkey_id_chirho.clone(),
                    error_chirho: error_chirho.to_string(),
                });
        }
    }

    Ok(report_chirho)
}

pub fn verify_run_cache_chirho(root_chirho: &Path) -> Result<RunCacheVerifyReportChirho> {
    let report_chirho = inspect_run_cache_chirho(root_chirho)?;
    ensure_run_cache_report_clean_chirho(&report_chirho)?;
    Ok(report_chirho)
}

pub fn ensure_run_cache_report_clean_chirho(
    report_chirho: &RunCacheVerifyReportChirho,
) -> Result<()> {
    if !report_chirho.missing_runkeys_chirho.is_empty()
        || !report_chirho.result_run_mismatches_chirho.is_empty()
        || !report_chirho.run_result_seal_failures_chirho.is_empty()
        || !report_chirho.runkey_hash_mismatches_chirho.is_empty()
        || !report_chirho.runkey_component_failures_chirho.is_empty()
    {
        bail!(
            "run cache verification failed: missing_runkeys={} result_run_mismatches={} run_result_seal_failures={} runkey_hash_mismatches={} runkey_component_failures={}",
            report_chirho.missing_runkeys_chirho.len(),
            report_chirho.result_run_mismatches_chirho.len(),
            report_chirho.run_result_seal_failures_chirho.len(),
            report_chirho.runkey_hash_mismatches_chirho.len(),
            report_chirho.runkey_component_failures_chirho.len()
        );
    }
    Ok(())
}

pub fn verify_volatile_effect_records_chirho(
    root_chirho: &Path,
) -> Result<VolatileEffectVerifyReportChirho> {
    let records_chirho = effect_chirho::load_volatile_effect_records_chirho(root_chirho)?;
    let mut objects_chirho = 0usize;
    for record_chirho in &records_chirho {
        let effect_chirho = &record_chirho.effect_chirho;
        verify_value_hash_or_private_chirho(root_chirho, &effect_chirho.request_chirho)?;
        objects_chirho += 1;
        if let Some(response_chirho) = &effect_chirho.response_chirho {
            verify_value_hash_or_private_chirho(root_chirho, response_chirho)?;
            objects_chirho += 1;
        }
    }
    Ok(VolatileEffectVerifyReportChirho {
        records_chirho: records_chirho.len(),
        objects_chirho,
    })
}

pub fn verify_run_intent_records_chirho(root_chirho: &Path) -> Result<usize> {
    effect_chirho::run_intent_chirho::verify_run_intent_records_chirho(root_chirho)
}

fn verify_run_objects_chirho(root_chirho: &Path, result_chirho: &RunResultChirho) -> Result<usize> {
    let mut n_chirho = 0usize;
    for hash_chirho in result_chirho.outputs_chirho.values() {
        verify_value_hash_or_private_chirho(root_chirho, hash_chirho)?;
        n_chirho += 1;
    }
    verify_object_hash_chirho(root_chirho, &result_chirho.trace_chirho)?;
    n_chirho += 1;
    for eff_chirho in &result_chirho.effects_chirho {
        effect_chirho::verify_effect_chirho(root_chirho, eff_chirho)?;
        verify_value_hash_or_private_chirho(root_chirho, &eff_chirho.request_chirho)?;
        n_chirho += 1;
        if let Some(resp_chirho) = &eff_chirho.response_chirho {
            verify_value_hash_or_private_chirho(root_chirho, resp_chirho)?;
            n_chirho += 1;
        }
    }
    Ok(n_chirho)
}

fn verify_run_cache_binding_chirho(
    root_chirho: &Path,
    expected_run_chirho: &HashChirho,
    result_chirho: &RunResultChirho,
) -> Result<usize> {
    cache_chirho::verify_run_result_seal_chirho(root_chirho, expected_run_chirho, result_chirho)?;
    let Some(run_key_chirho) = cache_chirho::load_run_key_chirho(root_chirho, expected_run_chirho)?
    else {
        bail!(
            "run {} is missing stored RunKeyChirho",
            expected_run_chirho.0
        );
    };
    let recomputed_chirho = store_chirho::hash_object_chirho(&run_key_chirho)?;
    if &recomputed_chirho != expected_run_chirho {
        bail!(
            "run key cache mismatch: run {} has RunKeyChirho hashing to {}",
            expected_run_chirho.0,
            recomputed_chirho.0
        );
    }
    Ok(1 + verify_run_key_components_chirho(root_chirho, expected_run_chirho, &run_key_chirho)?)
}

fn verify_run_key_components_chirho(
    root_chirho: &Path,
    run_chirho: &HashChirho,
    run_key_chirho: &RunKeyChirho,
) -> Result<usize> {
    let mut checked_chirho =
        verify_run_key_node_chirho(root_chirho, run_chirho, &run_key_chirho.node_chirho)?;
    for (port_chirho, input_chirho) in &run_key_chirho.inputs_chirho {
        verify_value_hash_or_private_chirho(root_chirho, input_chirho).with_context(|| {
            format!(
                "run {} RunKeyChirho input '{}' object {} failed verification",
                run_chirho.0, port_chirho, input_chirho.0
            )
        })?;
        checked_chirho += 1;
    }
    Ok(checked_chirho)
}

fn verify_run_key_node_chirho(
    root_chirho: &Path,
    run_chirho: &HashChirho,
    node_chirho: &HashChirho,
) -> Result<usize> {
    verify_object_hash_chirho(root_chirho, node_chirho).with_context(|| {
        format!(
            "run {} RunKeyChirho node object {} failed verification",
            run_chirho.0, node_chirho.0
        )
    })?;
    match store_chirho::get_object_chirho::<NodeDefChirho>(root_chirho, node_chirho) {
        Ok(node_def_chirho) => Ok(1 + verify_node_def_refs_chirho(
            root_chirho,
            run_chirho,
            node_chirho,
            &node_def_chirho,
        )?),
        Err(node_error_chirho) => {
            let _spec_chirho: native_worker_chirho::NativeProgramSpecChirho =
                store_chirho::get_object_chirho(root_chirho, node_chirho).with_context(|| {
                    format!(
                        "run {} RunKeyChirho node {} is neither NodeDefChirho nor NativeProgramSpecChirho; NodeDef decode failed: {node_error_chirho}",
                        run_chirho.0, node_chirho.0
                    )
                })?;
            native_worker_chirho::verify_native_program_chirho(root_chirho, node_chirho)
                .with_context(|| {
                    format!(
                        "run {} native RunKeyChirho spec {} failed verification",
                        run_chirho.0, node_chirho.0
                    )
                })?;
            Ok(2)
        }
    }
}

fn verify_node_def_refs_chirho(
    root_chirho: &Path,
    run_chirho: &HashChirho,
    node_chirho: &HashChirho,
    node_def_chirho: &NodeDefChirho,
) -> Result<usize> {
    let mut checked_chirho = 0usize;
    if let Some(spec_chirho) =
        native_worker_chirho::native_node_spec_from_impl_chirho(&node_def_chirho.impl_wasm_chirho)
    {
        native_worker_chirho::validate_native_node_def_chirho(
            root_chirho,
            node_def_chirho,
            &spec_chirho,
        )
        .with_context(|| {
            format!(
                "run {} native NodeDefChirho {} failed spec binding verification",
                run_chirho.0, node_chirho.0
            )
        })?;
        verify_object_hash_chirho(root_chirho, &spec_chirho).with_context(|| {
            format!(
                "run {} native NodeDefChirho {} spec {} failed verification",
                run_chirho.0, node_chirho.0, spec_chirho.0
            )
        })?;
        checked_chirho += 1;
        native_worker_chirho::verify_native_program_chirho(root_chirho, &spec_chirho)
            .with_context(|| {
                format!(
                    "run {} native NodeDefChirho {} spec {} failed executable verification",
                    run_chirho.0, node_chirho.0, spec_chirho.0
                )
            })?;
        checked_chirho += 1;
    } else if node_def_chirho.is_builtin_phi_chirho() {
        checked_chirho += 1;
    } else {
        verify_object_hash_chirho(root_chirho, &node_def_chirho.impl_wasm_chirho).with_context(
            || {
                format!(
                    "run {} NodeDefChirho {} impl {} failed verification",
                    run_chirho.0, node_chirho.0, node_def_chirho.impl_wasm_chirho.0
                )
            },
        )?;
        checked_chirho += 1;
    }
    for port_chirho in node_def_chirho
        .inputs_chirho
        .iter()
        .chain(node_def_chirho.outputs_chirho.iter())
    {
        verify_object_hash_chirho(root_chirho, &port_chirho.schema_chirho).with_context(|| {
            format!(
                "run {} NodeDefChirho {} port '{}' schema {} failed verification",
                run_chirho.0, node_chirho.0, port_chirho.name_chirho, port_chirho.schema_chirho.0
            )
        })?;
        checked_chirho += 1;
    }
    Ok(checked_chirho)
}

fn cache_dir_file_names_chirho(root_chirho: &Path, dir_chirho: &str) -> Result<BTreeSet<String>> {
    let path_chirho = root_chirho.join(dir_chirho);
    let mut names_chirho = BTreeSet::new();
    if !path_chirho.exists() {
        return Ok(names_chirho);
    }
    for entry_chirho in std::fs::read_dir(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?
    {
        let entry_chirho = entry_chirho?;
        if !entry_chirho.file_type()?.is_file() {
            continue;
        }
        let name_chirho = entry_chirho.file_name().into_string().map_err(|_| {
            anyhow::anyhow!(
                "{} contains a non-UTF-8 cache file name",
                path_chirho.display()
            )
        })?;
        names_chirho.insert(name_chirho);
    }
    Ok(names_chirho)
}

/// Why a content-addressed object did not verify, as three outcomes rather than one `Err`.
///
/// The distinction is the whole point: only [`Self::AbsentChirho`] may be rescued by looking for
/// the value on the private plane. Collapsing the three — which is what a bare `Result` does —
/// lets a TAMPERED public object be waved through by a private record that happens to claim the
/// same hash, on every surface that shares the fallback.
///
/// The three are resolved by `cas_chirho::read_verified_chirho` at the store itself, never
/// inferred here from "the read failed": "unreadable" is not "absent", and a corrupt object whose
/// READ fails must not be rescued either.
enum ObjectRefusalChirho {
    AbsentChirho(std::io::Error),
    TamperedChirho(HashChirho),
    UnreadableChirho(std::io::Error),
}

impl ObjectRefusalChirho {
    /// Absence is the ONLY outcome a caller may answer by looking somewhere else.
    fn may_fall_back_chirho(&self) -> bool {
        matches!(self, Self::AbsentChirho(_))
    }

    /// One refusal identity per outcome, built in one place so the three cannot drift apart
    /// between the surfaces that must tell them apart. None of the three shares a phrase with
    /// another: "missing", "tamper detected", "could not be read".
    fn into_error_chirho(self, hash_chirho: &HashChirho) -> anyhow::Error {
        match self {
            Self::AbsentChirho(error_chirho) => anyhow::Error::new(error_chirho)
                .context(format!("object {} missing", hash_chirho.0)),
            Self::TamperedChirho(actual_chirho) => anyhow::anyhow!(
                "tamper detected: object {} re-hashes to {}",
                hash_chirho.0,
                actual_chirho.0
            ),
            Self::UnreadableChirho(error_chirho) => anyhow::Error::new(error_chirho).context(
                format!("object {} is present but could not be read", hash_chirho.0),
            ),
        }
    }
}

/// Read an object, or say precisely why not. `Ok` means present AND re-hashing to its address.
fn read_object_or_refusal_chirho(
    root_chirho: &Path,
    hash_chirho: &HashChirho,
) -> std::result::Result<Vec<u8>, ObjectRefusalChirho> {
    match cas_chirho::read_verified_chirho(root_chirho, hash_chirho) {
        cas_chirho::CasReadOutcomeChirho::VerifiedChirho(bytes_chirho) => Ok(bytes_chirho),
        cas_chirho::CasReadOutcomeChirho::AbsentChirho(error_chirho) => {
            Err(ObjectRefusalChirho::AbsentChirho(error_chirho))
        }
        cas_chirho::CasReadOutcomeChirho::TamperedChirho { actual_chirho, .. } => {
            Err(ObjectRefusalChirho::TamperedChirho(actual_chirho))
        }
        cas_chirho::CasReadOutcomeChirho::UnreadableChirho(error_chirho) => {
            Err(ObjectRefusalChirho::UnreadableChirho(error_chirho))
        }
    }
}

/// Load an object and check it re-hashes to its content address (tamper-evidence).
fn verify_object_hash_chirho(root_chirho: &Path, hash_chirho: &HashChirho) -> Result<()> {
    match read_object_or_refusal_chirho(root_chirho, hash_chirho) {
        Ok(_bytes_chirho) => Ok(()),
        Err(refusal_chirho) => Err(refusal_chirho.into_error_chirho(hash_chirho)),
    }
}

/// A value hash verifies either as a public CAS object that re-hashes, or as a private DAG value
/// whose RECORD verifies — never merely because some line claims the hash.
///
/// F4 sealing (brick S3) makes this the normal path rather than a rare one: every live `ReadStore`
/// response is now a private DAG value, so a volatile-effect record's response hash routes through
/// here on every verify. That is why the fallback resolves through
/// `verified_private_dag_value_record_chirho` — schema, signature, subject and privacy-log coverage —
/// instead of the bare existence check it used before. An unresolvable private hash FAILS CLOSED:
/// a claimed-but-unverifiable record propagates its own loud error (the `?`), and a hash nothing
/// claims keeps the more accurate "object missing".
///
/// The fallback fires on ABSENCE ALONE. A public object that is present and does not re-hash is
/// tamper — the loudest signal this verifier can receive — and a private record claiming the same
/// hash must not convert it into a pass; likewise a present-but-unreadable object, whose failure
/// says nothing about whether the bytes are there. Both keep their own refusal identity, which is
/// why the fallback is gated on the OUTCOME rather than on `Err`.
fn verify_value_hash_or_private_chirho(root_chirho: &Path, hash_chirho: &HashChirho) -> Result<()> {
    let refusal_chirho = match read_object_or_refusal_chirho(root_chirho, hash_chirho) {
        Ok(_bytes_chirho) => return Ok(()),
        Err(refusal_chirho) => refusal_chirho,
    };
    if !refusal_chirho.may_fall_back_chirho() {
        return Err(refusal_chirho.into_error_chirho(hash_chirho));
    }
    match dag_private_value_chirho::verified_private_dag_value_record_chirho(
        root_chirho,
        hash_chirho,
    )? {
        Some(_record_chirho) => Ok(()),
        None => Err(refusal_chirho.into_error_chirho(hash_chirho)),
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::cache_chirho;
    use crate::model_chirho::{CapabilityChirho, DagChirho, EdgeChirho, NodeDefChirho, PortChirho};
    use crate::{dag_chirho, effect_chirho, store_chirho};
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
        std::env::temp_dir().join(format!("cairn-verify-test-{nanos_chirho}-{n_chirho}"))
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

    fn write_cache_json_chirho<T: serde::Serialize>(
        root_chirho: &Path,
        dir_chirho: &str,
        run_chirho: &HashChirho,
        value_chirho: &T,
    ) {
        let path_chirho = root_chirho.join(dir_chirho).join(&run_chirho.0);
        if let Some(parent_chirho) = path_chirho.parent() {
            std::fs::create_dir_all(parent_chirho).unwrap();
        }
        std::fs::write(
            path_chirho,
            serde_json::to_vec_pretty(value_chirho).unwrap(),
        )
        .unwrap();
    }

    fn cas_object_path_chirho(root_chirho: &Path, hash_chirho: &HashChirho) -> PathBuf {
        root_chirho
            .join("objects-chirho")
            .join(&hash_chirho.0[..2])
            .join(&hash_chirho.0[2..])
    }

    fn remove_cas_object_chirho(root_chirho: &Path, hash_chirho: &HashChirho) -> Vec<u8> {
        let bytes_chirho = cas_chirho::get_chirho(root_chirho, hash_chirho).unwrap();
        std::fs::remove_file(cas_object_path_chirho(root_chirho, hash_chirho)).unwrap();
        bytes_chirho
    }

    fn restore_cas_object_chirho(
        root_chirho: &Path,
        hash_chirho: &HashChirho,
        bytes_chirho: &[u8],
    ) {
        let restored_chirho = cas_chirho::add_chirho(root_chirho, bytes_chirho).unwrap();
        assert_eq!(&restored_chirho, hash_chirho);
    }

    #[test]
    fn verify_passes_then_detects_tamper_chirho() {
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
        let sink_run_chirho = report_chirho.node_runs_chirho[1].run_chirho.clone();

        // Genuine run verifies (objects checked > 0).
        assert!(verify_chirho(&root_chirho, &sink_run_chirho).unwrap() > 0);

        // Tamper the stored run result cache coordinate -> verification fails even though its
        // referenced CAS objects are still intact.
        let result_chirho = cache_chirho::load_result_chirho(&root_chirho, &sink_run_chirho)
            .unwrap()
            .unwrap();
        let mut mismatched_result_chirho = result_chirho.clone();
        mismatched_result_chirho.run_chirho = HashChirho("different-run-chirho".to_string());
        write_cache_json_chirho(
            &root_chirho,
            "runs-chirho",
            &sink_run_chirho,
            &mismatched_result_chirho,
        );
        let error_chirho = verify_chirho(&root_chirho, &sink_run_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("run result cache key mismatch"));
        write_cache_json_chirho(
            &root_chirho,
            "runs-chirho",
            &sink_run_chirho,
            &result_chirho,
        );

        // Remove or tamper the stored RunKeyChirho -> verification fails before trusting the run
        // coordinate as a valid cache key.
        let run_key_chirho = cache_chirho::load_run_key_chirho(&root_chirho, &sink_run_chirho)
            .unwrap()
            .unwrap();
        std::fs::remove_file(root_chirho.join("runkeys-chirho").join(&sink_run_chirho.0)).unwrap();
        let error_chirho = verify_chirho(&root_chirho, &sink_run_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("missing stored RunKeyChirho"));
        write_cache_json_chirho(
            &root_chirho,
            "runkeys-chirho",
            &sink_run_chirho,
            &run_key_chirho,
        );

        let mut mismatched_run_key_chirho = run_key_chirho.clone();
        mismatched_run_key_chirho.node_chirho = HashChirho("different-node-chirho".to_string());
        write_cache_json_chirho(
            &root_chirho,
            "runkeys-chirho",
            &sink_run_chirho,
            &mismatched_run_key_chirho,
        );
        let error_chirho = verify_chirho(&root_chirho, &sink_run_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("run key cache mismatch"));
        write_cache_json_chirho(
            &root_chirho,
            "runkeys-chirho",
            &sink_run_chirho,
            &run_key_chirho,
        );

        // Remove RunKeyChirho component CAS objects -> verification fails before claiming the
        // provenance can answer "by what code/input."
        let input_hash_chirho = run_key_chirho
            .inputs_chirho
            .values()
            .next()
            .unwrap()
            .clone();
        let input_bytes_chirho = remove_cas_object_chirho(&root_chirho, &input_hash_chirho);
        let error_chirho = verify_chirho(&root_chirho, &sink_run_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("RunKeyChirho input"));
        restore_cas_object_chirho(&root_chirho, &input_hash_chirho, &input_bytes_chirho);

        let node_bytes_chirho = remove_cas_object_chirho(&root_chirho, &run_key_chirho.node_chirho);
        let error_chirho = verify_chirho(&root_chirho, &sink_run_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("RunKeyChirho node object"));
        restore_cas_object_chirho(
            &root_chirho,
            &run_key_chirho.node_chirho,
            &node_bytes_chirho,
        );

        let node_def_chirho: NodeDefChirho =
            store_chirho::get_object_chirho(&root_chirho, &run_key_chirho.node_chirho).unwrap();
        let impl_bytes_chirho =
            remove_cas_object_chirho(&root_chirho, &node_def_chirho.impl_wasm_chirho);
        let error_chirho = verify_chirho(&root_chirho, &sink_run_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("impl"));
        restore_cas_object_chirho(
            &root_chirho,
            &node_def_chirho.impl_wasm_chirho,
            &impl_bytes_chirho,
        );

        // Rewrite the mutable RunResultChirho body to point at a different valid CAS object.
        // The old object-existence check could not distinguish this from a legitimate output;
        // the signed run-result seal now fails before the forged output is trusted.
        let forged_output_chirho = cas_chirho::add_chirho(&root_chirho, b"FORGED").unwrap();
        let mut forged_result_chirho = result_chirho.clone();
        let first_output_chirho = forged_result_chirho
            .outputs_chirho
            .keys()
            .next()
            .cloned()
            .unwrap();
        forged_result_chirho
            .outputs_chirho
            .insert(first_output_chirho, forged_output_chirho);
        write_cache_json_chirho(
            &root_chirho,
            "runs-chirho",
            &sink_run_chirho,
            &forged_result_chirho,
        );
        let error_chirho = verify_chirho(&root_chirho, &sink_run_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("run result seal hash mismatch"));
        write_cache_json_chirho(
            &root_chirho,
            "runs-chirho",
            &sink_run_chirho,
            &result_chirho,
        );

        // Tamper a stored output object on disk -> verification fails.
        let out_hash_chirho = result_chirho
            .outputs_chirho
            .values()
            .next()
            .unwrap()
            .clone();
        std::fs::write(
            cas_object_path_chirho(&root_chirho, &out_hash_chirho),
            b"tampered",
        )
        .unwrap();
        assert!(verify_chirho(&root_chirho, &sink_run_chirho).is_err());

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn run_cache_verify_reports_legacy_and_tampered_sidecars_chirho() {
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
        let sink_run_chirho = report_chirho.node_runs_chirho[1].run_chirho.clone();

        let clean_report_chirho = verify_run_cache_chirho(&root_chirho).unwrap();
        assert_eq!(clean_report_chirho.runs_chirho, 2);
        assert_eq!(clean_report_chirho.runkeys_chirho, 2);
        assert_eq!(clean_report_chirho.runseals_chirho, 2);
        assert!(clean_report_chirho.missing_runkeys_chirho.is_empty());
        assert!(clean_report_chirho.result_run_mismatches_chirho.is_empty());
        assert!(clean_report_chirho
            .run_result_seal_failures_chirho
            .is_empty());
        assert!(clean_report_chirho.runkey_hash_mismatches_chirho.is_empty());
        assert!(clean_report_chirho
            .runkey_component_failures_chirho
            .is_empty());
        assert!(clean_report_chirho.orphan_runkeys_chirho.is_empty());
        assert!(clean_report_chirho.orphan_runseals_chirho.is_empty());

        let result_chirho = cache_chirho::load_result_chirho(&root_chirho, &sink_run_chirho)
            .unwrap()
            .unwrap();
        let run_key_chirho = cache_chirho::load_run_key_chirho(&root_chirho, &sink_run_chirho)
            .unwrap()
            .unwrap();

        std::fs::remove_file(root_chirho.join("runkeys-chirho").join(&sink_run_chirho.0)).unwrap();
        let missing_report_chirho = inspect_run_cache_chirho(&root_chirho).unwrap();
        assert_eq!(
            missing_report_chirho.missing_runkeys_chirho,
            vec![sink_run_chirho.0.clone()]
        );
        let error_chirho = ensure_run_cache_report_clean_chirho(&missing_report_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("missing_runkeys=1"));
        write_cache_json_chirho(
            &root_chirho,
            "runkeys-chirho",
            &sink_run_chirho,
            &run_key_chirho,
        );

        let mut mismatched_result_chirho = result_chirho.clone();
        mismatched_result_chirho.run_chirho = HashChirho("wrong-run-chirho".to_string());
        write_cache_json_chirho(
            &root_chirho,
            "runs-chirho",
            &sink_run_chirho,
            &mismatched_result_chirho,
        );
        let result_report_chirho = inspect_run_cache_chirho(&root_chirho).unwrap();
        assert_eq!(
            result_report_chirho.result_run_mismatches_chirho,
            vec![RunCacheResultMismatchChirho {
                file_run_chirho: sink_run_chirho.0.clone(),
                declared_run_chirho: "wrong-run-chirho".to_string()
            }]
        );
        assert!(ensure_run_cache_report_clean_chirho(&result_report_chirho).is_err());
        write_cache_json_chirho(
            &root_chirho,
            "runs-chirho",
            &sink_run_chirho,
            &result_chirho,
        );

        let forged_output_chirho = cas_chirho::add_chirho(&root_chirho, b"FORGED").unwrap();
        let mut forged_result_chirho = result_chirho.clone();
        let first_output_chirho = forged_result_chirho
            .outputs_chirho
            .keys()
            .next()
            .cloned()
            .unwrap();
        forged_result_chirho
            .outputs_chirho
            .insert(first_output_chirho, forged_output_chirho);
        write_cache_json_chirho(
            &root_chirho,
            "runs-chirho",
            &sink_run_chirho,
            &forged_result_chirho,
        );
        let seal_report_chirho = inspect_run_cache_chirho(&root_chirho).unwrap();
        assert_eq!(seal_report_chirho.run_result_seal_failures_chirho.len(), 1);
        assert_eq!(
            seal_report_chirho.run_result_seal_failures_chirho[0].run_chirho,
            sink_run_chirho.0.clone()
        );
        assert!(seal_report_chirho.run_result_seal_failures_chirho[0]
            .error_chirho
            .contains("run result seal hash mismatch"));
        let error_chirho = ensure_run_cache_report_clean_chirho(&seal_report_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("run_result_seal_failures=1"));
        write_cache_json_chirho(
            &root_chirho,
            "runs-chirho",
            &sink_run_chirho,
            &result_chirho,
        );

        let mut mismatched_run_key_chirho = run_key_chirho.clone();
        mismatched_run_key_chirho.node_chirho = HashChirho("wrong-node-chirho".to_string());
        let mismatched_run_key_hash_chirho =
            store_chirho::hash_object_chirho(&mismatched_run_key_chirho).unwrap();
        write_cache_json_chirho(
            &root_chirho,
            "runkeys-chirho",
            &sink_run_chirho,
            &mismatched_run_key_chirho,
        );
        let key_report_chirho = inspect_run_cache_chirho(&root_chirho).unwrap();
        assert_eq!(
            key_report_chirho.runkey_hash_mismatches_chirho,
            vec![RunCacheRunKeyMismatchChirho {
                file_run_chirho: sink_run_chirho.0.clone(),
                computed_run_chirho: mismatched_run_key_hash_chirho.0
            }]
        );
        assert!(ensure_run_cache_report_clean_chirho(&key_report_chirho).is_err());
        write_cache_json_chirho(
            &root_chirho,
            "runkeys-chirho",
            &sink_run_chirho,
            &run_key_chirho,
        );

        let input_hash_chirho = run_key_chirho
            .inputs_chirho
            .values()
            .next()
            .unwrap()
            .clone();
        let input_bytes_chirho = remove_cas_object_chirho(&root_chirho, &input_hash_chirho);
        let component_report_chirho = inspect_run_cache_chirho(&root_chirho).unwrap();
        assert_eq!(
            component_report_chirho
                .runkey_component_failures_chirho
                .len(),
            1
        );
        assert_eq!(
            component_report_chirho.runkey_component_failures_chirho[0].run_chirho,
            sink_run_chirho.0
        );
        assert!(component_report_chirho.runkey_component_failures_chirho[0]
            .error_chirho
            .contains("RunKeyChirho input"));
        let error_chirho = ensure_run_cache_report_clean_chirho(&component_report_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("runkey_component_failures=1"));
        restore_cas_object_chirho(&root_chirho, &input_hash_chirho, &input_bytes_chirho);

        let mut orphan_run_key_chirho = run_key_chirho.clone();
        let orphan_input_hash_chirho =
            cas_chirho::add_chirho(&root_chirho, b"orphan input chirho").unwrap();
        orphan_run_key_chirho
            .inputs_chirho
            .insert("orphan_chirho".to_string(), orphan_input_hash_chirho);
        let orphan_hash_chirho = store_chirho::hash_object_chirho(&orphan_run_key_chirho).unwrap();
        write_cache_json_chirho(
            &root_chirho,
            "runkeys-chirho",
            &orphan_hash_chirho,
            &orphan_run_key_chirho,
        );
        let orphan_report_chirho = verify_run_cache_chirho(&root_chirho).unwrap();
        assert_eq!(orphan_report_chirho.runs_chirho, 2);
        assert_eq!(orphan_report_chirho.runkeys_chirho, 3);
        assert!(orphan_report_chirho
            .runkey_component_failures_chirho
            .is_empty());
        assert_eq!(
            orphan_report_chirho.orphan_runkeys_chirho,
            vec![orphan_hash_chirho.0.clone()]
        );
        let orphan_seal_chirho = HashChirho("orphan-run-seal-chirho".to_string());
        let orphan_seal_json_chirho = serde_json::json!({
            "schema_chirho": cache_chirho::RUN_RESULT_SEAL_SCHEMA_CHIRHO,
            "run_chirho": orphan_seal_chirho,
            "result_hash_chirho": orphan_hash_chirho,
            "sig_chirho": "invalid"
        });
        write_cache_json_chirho(
            &root_chirho,
            "runseals-chirho",
            &HashChirho("orphan-run-seal-chirho".to_string()),
            &orphan_seal_json_chirho,
        );
        let orphan_seal_report_chirho = verify_run_cache_chirho(&root_chirho).unwrap();
        assert_eq!(
            orphan_seal_report_chirho.orphan_runseals_chirho,
            vec!["orphan-run-seal-chirho".to_string()]
        );

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn verify_volatile_effect_records_checks_signed_rows_and_cas_chirho() {
        let root_chirho = tmp_root_chirho();
        {
            let store_chirho = crate::versioned_chirho::VersionedStoreChirho::open_chirho(
                &root_chirho.join("versioned-chirho.redb"),
            )
            .unwrap();
            store_chirho.put_chirho("user/alice", b"a").unwrap();
        }
        let capability_chirho = CapabilityChirho::ReadStoreChirho {
            prefix_chirho: "user/alice".to_string(),
        };
        effect_chirho::run_effect_chirho(
            &root_chirho,
            0,
            HashChirho("verify-read-idem".to_string()),
            capability_chirho.clone(),
            b"",
        )
        .unwrap();
        {
            let store_chirho = crate::versioned_chirho::VersionedStoreChirho::open_chirho(
                &root_chirho.join("versioned-chirho.redb"),
            )
            .unwrap();
            store_chirho.put_chirho("user/bob", b"b").unwrap();
            store_chirho.put_chirho("user/alice", b"refreshed").unwrap();
        }
        effect_chirho::run_effect_chirho(
            &root_chirho,
            1,
            HashChirho("verify-read-idem".to_string()),
            capability_chirho,
            b"",
        )
        .unwrap();

        let report_chirho = verify_volatile_effect_records_chirho(&root_chirho).unwrap();
        assert_eq!(report_chirho.records_chirho, 2);
        assert_eq!(report_chirho.objects_chirho, 4);

        let records_chirho =
            effect_chirho::load_volatile_effect_records_chirho(&root_chirho).unwrap();
        let response_hash_chirho = records_chirho[0]
            .effect_chirho
            .response_chirho
            .clone()
            .unwrap();
        let obj_path_chirho = root_chirho
            .join("objects-chirho")
            .join(&response_hash_chirho.0[..2])
            .join(&response_hash_chirho.0[2..]);
        std::fs::write(&obj_path_chirho, b"tampered-live-response").unwrap();
        assert!(verify_volatile_effect_records_chirho(&root_chirho).is_err());

        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
