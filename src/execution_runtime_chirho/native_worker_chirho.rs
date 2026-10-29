// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Runs content-addressed native workers through the same cache and audit shape as WASM nodes.

use crate::model_chirho::{
    CapabilityChirho, HashChirho, NodeDefChirho, PortChirho, RequestContextChirho, RunKeyChirho,
    RunResultChirho, RunStatusChirho, NATIVE_NODE_IMPL_PREFIX_CHIRHO,
};
use crate::{cache_chirho, cas_chirho, effect_chirho, store_chirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const NATIVE_PROGRAM_SCHEMA_CHIRHO: &str = "native-program/v1-chirho";
const NATIVE_ABI_BYTES_STDIO_CHIRHO: &str = "bytes-stdio-once/v1-chirho";
const NATIVE_ABI_BYTES_STDIO_FRAMED_CHIRHO: &str = "bytes-stdio-framed/v1-chirho";
// `NATIVE_NODE_IMPL_PREFIX_CHIRHO` moved to `cairn-core-chirho::model_chirho` (imported above): one

#[path = "native_worker_chirho/stateless_chirho.rs"]
mod stateless_chirho;
#[path = "native_worker_chirho/warm_pool_chirho.rs"]
mod warm_pool_chirho;
use stateless_chirho::native_program_has_stateless_attestation_chirho;
pub use stateless_chirho::{
    attest_native_program_stateless_chirho, load_native_stateless_attestations_chirho,
    verify_native_stateless_attestations_chirho,
};
pub use warm_pool_chirho::{prewarm_native_program_chirho, shutdown_native_warm_pool_chirho};
use warm_pool_chirho::{
    run_native_program_pooled_chirho, run_native_stateless_probe_once_chirho,
    run_native_stateless_probe_reused_chirho,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeSandboxModeChirho {
    RequiredSeccompChirho,
    BestEffortChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeProgramSpecChirho {
    pub schema_chirho: String,
    pub name_chirho: String,
    pub executable_chirho: HashChirho,
    pub registered_by_chirho: String,
    pub registered_pubkey_chirho: String,
    pub sig_chirho: String,
    pub argv_chirho: Vec<String>,
    pub abi_chirho: String,
    pub sandbox_mode_chirho: NativeSandboxModeChirho,
    pub allowed_syscalls_chirho: Vec<String>,
    pub capabilities_chirho: Vec<CapabilityChirho>,
    pub timeout_ms_chirho: u64,
    pub max_memory_bytes_chirho: u64,
    pub max_input_bytes_chirho: usize,
    pub max_output_bytes_chirho: usize,
    pub warm_pool_size_chirho: usize,
    pub scope_notes_chirho: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeProgramBuildRequestChirho {
    pub name_chirho: String,
    pub argv_chirho: Vec<String>,
    pub sandbox_mode_chirho: NativeSandboxModeChirho,
    pub allowed_syscalls_chirho: Vec<String>,
    pub capabilities_chirho: Vec<CapabilityChirho>,
    pub timeout_ms_chirho: u64,
    pub max_memory_bytes_chirho: u64,
    pub max_input_bytes_chirho: usize,
    pub max_output_bytes_chirho: usize,
    pub warm_pool_size_chirho: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSandboxStatusChirho {
    pub platform_chirho: String,
    pub seccomp_enforced_chirho: bool,
    pub reason_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeWarmPoolChirho {
    pub spec_chirho: HashChirho,
    pub executable_chirho: HashChirho,
    pub materialized_executable_chirho: String,
    pub warm_slots_chirho: usize,
    pub sandbox_chirho: NativeSandboxStatusChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeRunOutcomeChirho {
    pub output_chirho: Vec<u8>,
    pub elapsed_ms_chirho: u64,
    pub sandbox_chirho: NativeSandboxStatusChirho,
    pub pooled_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeProgramVerificationChirho {
    pub spec_chirho: HashChirho,
    pub executable_chirho: HashChirho,
    pub registered_by_chirho: String,
    pub registered_pubkey_chirho: String,
    pub signature_valid_chirho: bool,
    pub abi_chirho: String,
    pub pure_chirho: bool,
    pub sandbox_chirho: NativeSandboxStatusChirho,
    pub allowed_syscalls_chirho: Vec<String>,
    pub stateless_attested_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeStatelessAttestationRecordChirho {
    pub seq_chirho: u64,
    pub spec_chirho: HashChirho,
    pub executable_chirho: HashChirho,
    pub abi_chirho: String,
    pub method_chirho: String,
    pub probe_input_chirho: HashChirho,
    pub fresh_output_chirho: HashChirho,
    pub reused_first_output_chirho: HashChirho,
    pub reused_second_output_chirho: HashChirho,
    pub output_len_chirho: usize,
    pub sandbox_chirho: NativeSandboxStatusChirho,
    pub attested_by_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

pub fn default_native_syscalls_chirho() -> Vec<String> {
    [
        "arch_prctl",
        "brk",
        "close",
        "execve",
        "exit",
        "exit_group",
        "futex",
        "mmap",
        "mprotect",
        "munmap",
        "read",
        "rseq",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "set_robust_list",
        "set_tid_address",
        "write",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

pub fn build_native_program_chirho(
    root_chirho: &Path,
    executable_chirho: &Path,
    request_chirho: NativeProgramBuildRequestChirho,
) -> Result<(NativeProgramSpecChirho, HashChirho)> {
    build_native_program_with_abi_chirho(
        root_chirho,
        executable_chirho,
        request_chirho,
        NATIVE_ABI_BYTES_STDIO_CHIRHO,
    )
}

pub fn native_abi_bytes_stdio_framed_chirho() -> &'static str {
    NATIVE_ABI_BYTES_STDIO_FRAMED_CHIRHO
}

pub fn build_native_program_with_abi_chirho(
    root_chirho: &Path,
    executable_chirho: &Path,
    request_chirho: NativeProgramBuildRequestChirho,
    abi_chirho: &str,
) -> Result<(NativeProgramSpecChirho, HashChirho)> {
    let bytes_chirho = std::fs::read(executable_chirho)
        .with_context(|| format!("read native executable {}", executable_chirho.display()))?;
    let executable_hash_chirho = cas_chirho::add_chirho(root_chirho, &bytes_chirho)?;
    let raw_syscalls_chirho = if request_chirho.allowed_syscalls_chirho.is_empty() {
        default_native_syscalls_chirho()
    } else {
        request_chirho.allowed_syscalls_chirho
    };
    let allowed_syscalls_chirho = canonical_syscalls_chirho(&raw_syscalls_chirho)?;
    let mut spec_chirho = NativeProgramSpecChirho {
        schema_chirho: NATIVE_PROGRAM_SCHEMA_CHIRHO.to_string(),
        name_chirho: validate_token_chirho("native program name", &request_chirho.name_chirho)?,
        executable_chirho: executable_hash_chirho,
        registered_by_chirho: "owner/platform-native-tier-chirho".to_string(),
        registered_pubkey_chirho: signer_chirho::pubkey_hex_chirho(root_chirho)?,
        sig_chirho: String::new(),
        argv_chirho: request_chirho
            .argv_chirho
            .iter()
            .map(|arg_chirho| validate_arg_chirho(arg_chirho))
            .collect::<Result<Vec<_>>>()?,
        abi_chirho: validate_native_abi_chirho(abi_chirho)?.to_string(),
        sandbox_mode_chirho: request_chirho.sandbox_mode_chirho,
        allowed_syscalls_chirho,
        capabilities_chirho: canonical_capabilities_chirho(&request_chirho.capabilities_chirho)?,
        timeout_ms_chirho: request_chirho.timeout_ms_chirho,
        max_memory_bytes_chirho: request_chirho.max_memory_bytes_chirho,
        max_input_bytes_chirho: request_chirho.max_input_bytes_chirho,
        max_output_bytes_chirho: request_chirho.max_output_bytes_chirho,
        warm_pool_size_chirho: request_chirho.warm_pool_size_chirho,
        scope_notes_chirho: vec![
            "Tier-2 native workers are an escape hatch for hot paths; Tier 1 WASM remains the default.".to_string(),
            "The host owns effects. Native code receives bytes and stdout only; non-empty capabilities are host-mediated blessed-effect adapters, not arbitrary effectful native binary execution.".to_string(),
            "RequiredSeccompChirho fails closed when Linux seccomp is unavailable; BestEffortChirho is for local development only.".to_string(),
            "Cacheable pure native workers use a deliberately narrow deterministic syscall profile; clock, randomness, filesystem, and network syscalls are rejected.".to_string(),
            "Linux RequiredSeccompChirho expects a static/no-post-exec-file-open worker unless the syscall profile deliberately admits startup file syscalls.".to_string(),
            "Framed warm-pool workers must be admitted as stateless request loops; pooled runs are treated as volatile until cairn can prove or attest that invariant.".to_string(),
        ],
    };
    let message_chirho = native_spec_message_chirho(&spec_chirho)?;
    spec_chirho.sig_chirho = signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
    validate_native_program_chirho(&spec_chirho)?;
    verify_native_spec_signature_chirho(root_chirho, &spec_chirho)?;
    let spec_hash_chirho = store_chirho::put_object_chirho(root_chirho, &spec_chirho)?;
    Ok((spec_chirho, spec_hash_chirho))
}

pub fn load_native_program_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
) -> Result<NativeProgramSpecChirho> {
    let spec_obj_chirho: NativeProgramSpecChirho =
        store_chirho::get_object_chirho(root_chirho, spec_chirho).with_context(|| {
            format!(
                "NativeProgramSpecChirho {} is not in the store",
                spec_chirho.0
            )
        })?;
    validate_native_program_chirho(&spec_obj_chirho)?;
    verify_native_spec_signature_chirho(root_chirho, &spec_obj_chirho)?;
    Ok(spec_obj_chirho)
}

pub fn verify_native_program_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
) -> Result<NativeProgramVerificationChirho> {
    let spec_obj_chirho = load_native_program_chirho(root_chirho, spec_chirho)?;
    let executable_bytes_chirho =
        cas_chirho::get_chirho(root_chirho, &spec_obj_chirho.executable_chirho).with_context(
            || {
                format!(
                    "native executable {} not in CAS",
                    spec_obj_chirho.executable_chirho.0
                )
            },
        )?;
    let recomputed_chirho = cas_chirho::hash_chirho(&executable_bytes_chirho);
    if recomputed_chirho != spec_obj_chirho.executable_chirho {
        bail!("native executable CAS hash mismatch");
    }
    Ok(NativeProgramVerificationChirho {
        spec_chirho: spec_chirho.clone(),
        executable_chirho: spec_obj_chirho.executable_chirho.clone(),
        registered_by_chirho: spec_obj_chirho.registered_by_chirho.clone(),
        registered_pubkey_chirho: spec_obj_chirho.registered_pubkey_chirho.clone(),
        signature_valid_chirho: verify_native_spec_signature_chirho(root_chirho, &spec_obj_chirho)?,
        abi_chirho: spec_obj_chirho.abi_chirho.clone(),
        pure_chirho: spec_obj_chirho.capabilities_chirho.is_empty(),
        sandbox_chirho: sandbox_status_chirho(&spec_obj_chirho),
        allowed_syscalls_chirho: spec_obj_chirho.allowed_syscalls_chirho.clone(),
        stateless_attested_chirho: native_program_has_stateless_attestation_chirho(
            root_chirho,
            spec_chirho,
            &spec_obj_chirho,
        )?,
    })
}

pub fn native_node_impl_hash_chirho(spec_chirho: &HashChirho) -> HashChirho {
    HashChirho(format!(
        "{}{}",
        NATIVE_NODE_IMPL_PREFIX_CHIRHO, spec_chirho.0
    ))
}

pub fn native_node_spec_from_impl_chirho(impl_chirho: &HashChirho) -> Option<HashChirho> {
    impl_chirho
        .0
        .strip_prefix(NATIVE_NODE_IMPL_PREFIX_CHIRHO)
        .filter(|spec_chirho| !spec_chirho.is_empty())
        .map(|spec_chirho| HashChirho(spec_chirho.to_string()))
}

pub fn build_native_node_def_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
    name_chirho: Option<String>,
) -> Result<(NodeDefChirho, HashChirho)> {
    let spec_obj_chirho = load_native_program_chirho(root_chirho, spec_chirho)?;
    let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes")?;
    let node_chirho = NodeDefChirho {
        name_chirho: validate_token_chirho(
            "native node name",
            name_chirho
                .as_deref()
                .unwrap_or(&spec_obj_chirho.name_chirho),
        )?,
        impl_wasm_chirho: native_node_impl_hash_chirho(spec_chirho),
        entry_chirho: "native_chirho".to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho: spec_obj_chirho.capabilities_chirho.clone(),
        fuel_limit_chirho: 0,
        ..Default::default()
    };
    validate_native_node_def_chirho(root_chirho, &node_chirho, spec_chirho)?;
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho)?;
    Ok((node_chirho, node_hash_chirho))
}

pub fn validate_native_node_def_chirho(
    root_chirho: &Path,
    node_def_chirho: &NodeDefChirho,
    spec_chirho: &HashChirho,
) -> Result<NativeProgramSpecChirho> {
    if native_node_spec_from_impl_chirho(&node_def_chirho.impl_wasm_chirho).as_ref()
        != Some(spec_chirho)
    {
        bail!(
            "native node '{}' impl hash does not point at native spec {}",
            node_def_chirho.name_chirho,
            spec_chirho.0
        );
    }
    if node_def_chirho.entry_chirho != "native_chirho" {
        bail!(
            "native node '{}' must use entry native_chirho",
            node_def_chirho.name_chirho
        );
    }
    if node_def_chirho.inputs_chirho.len() != 1 || node_def_chirho.outputs_chirho.len() != 1 {
        bail!(
            "native node '{}' must expose one input and one output port",
            node_def_chirho.name_chirho
        );
    }
    if node_def_chirho.fuel_limit_chirho != 0 {
        bail!(
            "native node '{}' must use fuel_limit_chirho=0; native limits live in NativeProgramSpecChirho",
            node_def_chirho.name_chirho
        );
    }
    let spec_obj_chirho = load_native_program_chirho(root_chirho, spec_chirho)?;
    if node_def_chirho.capabilities_chirho != spec_obj_chirho.capabilities_chirho {
        bail!(
            "native node '{}' capabilities must match its NativeProgramSpecChirho",
            node_def_chirho.name_chirho
        );
    }
    Ok(spec_obj_chirho)
}

pub fn run_native_program_cached_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
    input_hash_chirho: &HashChirho,
    parents_chirho: &[HashChirho],
) -> Result<(RunResultChirho, bool)> {
    run_native_program_cached_with_context_chirho(
        root_chirho,
        spec_chirho,
        input_hash_chirho,
        parents_chirho,
        None,
    )
}

pub fn run_native_program_cached_with_context_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
    input_hash_chirho: &HashChirho,
    parents_chirho: &[HashChirho],
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<(RunResultChirho, bool)> {
    run_native_program_node_cached_with_context_chirho(
        root_chirho,
        spec_chirho,
        spec_chirho,
        input_hash_chirho,
        parents_chirho,
        request_context_chirho,
    )
}

/// Explicit node-less/operator entry. App DAG execution uses the verified-node entry below. Being the
/// operator's, a run here with no request context puts its private values in no account.
pub fn run_native_program_node_cached_with_context_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
    node_hash_chirho: &HashChirho,
    input_hash_chirho: &HashChirho,
    parents_chirho: &[HashChirho],
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<(RunResultChirho, bool)> {
    let operator_chirho =
        crate::privacy_chirho::PrivateBlobAttributionChirho::not_account_scoped_chirho(
            crate::privacy_chirho::NotAccountScopedReasonChirho::OperatorRunChirho,
        );
    run_native_program_node_cached_with_admission_chirho(
        root_chirho,
        spec_chirho,
        node_hash_chirho,
        input_hash_chirho,
        parents_chirho,
        None,
        crate::dag_private_value_chirho::RunAttributionSourceChirho::new_chirho(
            request_context_chirho,
            Some(&operator_chirho),
        ),
    )
}

/// Runs a DAG-owned native node with descriptor-v2 admission before cache lookup or billing.
/// Workflow: `spec-chirho/workflows-chirho/undo-chirho/static-undo-plan-design-chirho.md` 4.2.1.
pub(crate) fn run_verified_native_node_cached_with_context_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
    node_def_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
    input_hash_chirho: &HashChirho,
    parents_chirho: &[HashChirho],
    // The run's source, which also carries its request context.
    attribution_source_chirho: crate::dag_private_value_chirho::RunAttributionSourceChirho<'_>,
) -> Result<(RunResultChirho, bool)> {
    validate_native_node_def_chirho(root_chirho, node_def_chirho, spec_chirho)?;
    run_native_program_node_cached_with_admission_chirho(
        root_chirho,
        spec_chirho,
        node_hash_chirho,
        input_hash_chirho,
        parents_chirho,
        Some(node_def_chirho),
        attribution_source_chirho,
    )
}

fn run_native_program_node_cached_with_admission_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
    node_hash_chirho: &HashChirho,
    input_hash_chirho: &HashChirho,
    parents_chirho: &[HashChirho],
    verified_node_def_chirho: Option<&NodeDefChirho>,
    attribution_source_chirho: crate::dag_private_value_chirho::RunAttributionSourceChirho<'_>,
) -> Result<(RunResultChirho, bool)> {
    let request_context_chirho = attribution_source_chirho.request_context_chirho();
    let spec_obj_chirho = load_native_program_chirho(root_chirho, spec_chirho)?;
    let effective_spec_chirho =
        contextual_native_program_chirho(&spec_obj_chirho, request_context_chirho)?;
    let sandbox_chirho = sandbox_status_chirho(&spec_obj_chirho);
    let capability_chirho = executable_capability_chirho(&effective_spec_chirho)?;
    if let Some(CapabilityChirho::InvokeChirho {
        node_chirho: target_node_chirho,
    }) = &capability_chirho
    {
        if target_node_chirho == node_hash_chirho {
            bail!("native InvokeChirho node cannot invoke itself");
        }
    }
    let effect_volatile_chirho = capability_chirho
        .as_ref()
        .is_some_and(effect_chirho::is_volatile_chirho);
    if request_context_chirho.is_none()
        && matches!(
            &capability_chirho,
            Some(CapabilityChirho::PaidEffectChirho { .. })
        )
    {
        bail!("charge-bearing PaidEffectChirho requires verified RequestContextChirho");
    }
    let effect_admission_chirho = capability_chirho
        .as_ref()
        .map(|capability_chirho| match verified_node_def_chirho {
            Some(node_def_chirho) => crate::blessed_chirho::admit_verified_node_effect_chirho(
                node_def_chirho,
                node_hash_chirho,
                capability_chirho,
            ),
            None => crate::blessed_chirho::admit_legacy_operator_effect_chirho(capability_chirho),
        })
        .transpose()?;
    let may_reuse_generic_effect_result_chirho = effect_admission_chirho
        .as_ref()
        .map(crate::blessed_chirho::EffectAdmissionChirho::may_reuse_generic_effect_result_chirho)
        .transpose()?
        .unwrap_or(true);
    let verified_asset_input_chirho = match effect_admission_chirho.as_ref() {
        Some(admission_chirho) if admission_chirho.requires_asset_op_request_chirho() => {
            let input_bytes_chirho = cas_chirho::get_chirho(root_chirho, input_hash_chirho)
                .with_context(|| format!("native input {} not in store", input_hash_chirho.0))?;
            if input_bytes_chirho.len() > spec_obj_chirho.max_input_bytes_chirho {
                bail!(
                    "native input has {} bytes, over max {}",
                    input_bytes_chirho.len(),
                    spec_obj_chirho.max_input_bytes_chirho
                );
            }
            admission_chirho.authorize_request_chirho(&input_bytes_chirho)?;
            Some(input_bytes_chirho)
        }
        _ => None,
    };
    let key_chirho =
        build_native_run_key_chirho(&effective_spec_chirho, node_hash_chirho, input_hash_chirho)?;
    let run_hash_chirho = store_chirho::hash_object_chirho(&key_chirho)?;
    cache_chirho::store_run_key_chirho(root_chirho, &run_hash_chirho, &key_chirho)?;
    let unsupported_pure_native_chirho =
        capability_chirho.is_none() && !sandbox_chirho.seccomp_enforced_chirho;
    let framed_pool_native_chirho = capability_chirho.is_none()
        && effective_spec_chirho.abi_chirho == NATIVE_ABI_BYTES_STDIO_FRAMED_CHIRHO;
    let stateless_attested_chirho = native_program_has_stateless_attestation_chirho(
        root_chirho,
        spec_chirho,
        &effective_spec_chirho,
    )?;
    let volatile_chirho = effect_volatile_chirho
        || unsupported_pure_native_chirho
        || (framed_pool_native_chirho && !stateless_attested_chirho);
    if !volatile_chirho && may_reuse_generic_effect_result_chirho {
        let cached_chirho = if capability_chirho.is_some() {
            cache_chirho::load_sealed_result_chirho(root_chirho, &run_hash_chirho)?
        } else {
            cache_chirho::load_resealable_pure_result_chirho(root_chirho, &run_hash_chirho)?
        };
        if let Some(cached_chirho) = cached_chirho {
            let cached_chirho = cached_with_current_parents_chirho(
                root_chirho,
                cached_chirho,
                parents_chirho,
                capability_chirho.as_ref(),
            )?;
            if let Some(capability_chirho) = capability_chirho.as_ref() {
                cache_chirho::bill_cached_paid_effect_chirho(
                    root_chirho,
                    capability_chirho,
                    &run_hash_chirho,
                    request_context_chirho,
                )?;
            }
            if let Some(capability_chirho) = capability_chirho.as_ref() {
                cache_chirho::bill_cached_invoked_paid_effects_chirho(
                    root_chirho,
                    &cached_chirho,
                    capability_chirho,
                    request_context_chirho,
                )?;
            }
            return Ok((cached_chirho, true));
        }
    }
    let input_bytes_chirho = match verified_asset_input_chirho {
        Some(input_bytes_chirho) => input_bytes_chirho,
        None => cas_chirho::get_chirho(root_chirho, input_hash_chirho)
            .with_context(|| format!("native input {} not in store", input_hash_chirho.0))?,
    };
    if input_bytes_chirho.len() > spec_obj_chirho.max_input_bytes_chirho {
        bail!(
            "native input has {} bytes, over max {}",
            input_bytes_chirho.len(),
            spec_obj_chirho.max_input_bytes_chirho
        );
    }
    let (
        output_hash_chirho,
        effects_chirho,
        fuel_used_chirho,
        trace_extra_chirho,
        invoked_parent_chirho,
    ) = if let Some(capability_chirho) = capability_chirho {
        enforce_identity_for_native_effect_chirho(&effective_spec_chirho, &capability_chirho)?;
        let admission_chirho = effect_admission_chirho
            .as_ref()
            .context("native effect execution is missing its admission token")?;
        let effect_chirho =
            effect_chirho::run_admitted_effect_with_context_and_value_storage_chirho(
                root_chirho,
                0,
                run_hash_chirho.clone(),
                capability_chirho,
                &input_bytes_chirho,
                effect_chirho::AdmittedEffectRunOptionsChirho {
                    storage_chirho: effect_chirho::EffectValueStorageChirho::default(),
                    request_context_chirho,
                    attribution_source_chirho,
                    admission_chirho,
                    postgres_reversible_chirho: None,
                    llm_served_chirho: None,
                },
            )?;
        let effect_response_hash_chirho = effect_chirho
            .response_chirho
            .clone()
            .ok_or_else(|| anyhow!("native effect produced no response"))?;
        let (output_hash_chirho, invoked_parent_chirho) =
            cache_chirho::effect_output_and_invoked_parent_chirho(
                root_chirho,
                &effect_chirho.capability_chirho,
                &effect_response_hash_chirho,
            )?;
        (
            output_hash_chirho,
            vec![effect_chirho],
            0,
            "effect=host-mediated".to_string(),
            invoked_parent_chirho,
        )
    } else {
        let outcome_chirho = run_native_program_uncached_chirho(
            root_chirho,
            spec_chirho,
            &spec_obj_chirho,
            &input_bytes_chirho,
        )?;
        let output_hash_chirho =
            cas_chirho::add_chirho(root_chirho, &outcome_chirho.output_chirho)?;
        (
            output_hash_chirho,
            Vec::new(),
            0,
            format!(
                "sandbox_enforced={} pooled={} elapsed_ms={}",
                outcome_chirho.sandbox_chirho.seccomp_enforced_chirho,
                outcome_chirho.pooled_chirho,
                outcome_chirho.elapsed_ms_chirho
            ),
            None,
        )
    };
    let mut outputs_chirho = BTreeMap::new();
    outputs_chirho.insert("out".to_string(), output_hash_chirho);
    let trace_text_chirho = format!(
        "tier=native node={} node_hash={} spec={} executable={} abi={} syscalls={:?} admitted_by={} sandbox_enforced={} stateless_attested={} cacheable={} in={} {}",
        spec_obj_chirho.name_chirho,
        node_hash_chirho.0,
        spec_chirho.0,
        spec_obj_chirho.executable_chirho.0,
        spec_obj_chirho.abi_chirho,
        spec_obj_chirho.allowed_syscalls_chirho,
        spec_obj_chirho.registered_by_chirho,
        sandbox_chirho.seccomp_enforced_chirho,
        stateless_attested_chirho,
        !volatile_chirho,
        input_hash_chirho.0,
        trace_extra_chirho
    );
    let trace_hash_chirho = cas_chirho::add_chirho(root_chirho, trace_text_chirho.as_bytes())?;
    let result_chirho = RunResultChirho {
        run_chirho: run_hash_chirho,
        outputs_chirho,
        effects_chirho,
        fuel_used_chirho,
        trace_chirho: trace_hash_chirho,
        status_chirho: RunStatusChirho::OkChirho,
        parents_chirho: cache_chirho::parents_with_invoked_parent_chirho(
            parents_chirho,
            invoked_parent_chirho,
        ),
    };
    if !volatile_chirho {
        cache_chirho::store_result_chirho(root_chirho, &result_chirho)?;
    }
    Ok((result_chirho, false))
}

pub fn run_native_program_uncached_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
    spec_obj_chirho: &NativeProgramSpecChirho,
    input_chirho: &[u8],
) -> Result<NativeRunOutcomeChirho> {
    if !spec_obj_chirho.capabilities_chirho.is_empty() {
        bail!("native executable runs are pure only; granted effects are host-mediated");
    }
    validate_native_program_chirho(spec_obj_chirho)?;
    let sandbox_chirho = sandbox_status_chirho(spec_obj_chirho);
    if matches!(
        spec_obj_chirho.sandbox_mode_chirho,
        NativeSandboxModeChirho::RequiredSeccompChirho
    ) && !sandbox_chirho.seccomp_enforced_chirho
    {
        bail!(
            "native worker requires seccomp but this platform cannot enforce it: {}",
            sandbox_chirho.reason_chirho
        );
    }
    if spec_obj_chirho.abi_chirho == NATIVE_ABI_BYTES_STDIO_FRAMED_CHIRHO {
        return run_native_program_pooled_chirho(
            root_chirho,
            spec_chirho,
            spec_obj_chirho,
            input_chirho,
            sandbox_chirho,
        );
    }
    let executable_path_chirho =
        materialize_native_executable_chirho(root_chirho, spec_chirho, spec_obj_chirho)?;
    let started_chirho = Instant::now();
    let mut command_chirho = Command::new(executable_path_chirho);
    command_chirho
        .args(&spec_obj_chirho.argv_chirho)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    apply_pre_exec_sandbox_chirho(&mut command_chirho, spec_obj_chirho)?;
    let mut child_chirho = command_chirho.spawn().context("spawn native worker")?;
    if let Some(mut stdin_chirho) = child_chirho.stdin.take() {
        stdin_chirho
            .write_all(input_chirho)
            .context("write native worker stdin")?;
    }
    let stdout_chirho = child_chirho
        .stdout
        .take()
        .ok_or_else(|| anyhow!("native worker stdout was not captured"))?;
    let stderr_chirho = child_chirho
        .stderr
        .take()
        .ok_or_else(|| anyhow!("native worker stderr was not captured"))?;
    let stdout_reader_chirho = thread::spawn(move || read_pipe_chirho(stdout_chirho));
    let stderr_reader_chirho = thread::spawn(move || read_pipe_chirho(stderr_chirho));
    let timeout_chirho = Duration::from_millis(spec_obj_chirho.timeout_ms_chirho);
    let status_chirho = loop {
        if let Some(status_chirho) = child_chirho.try_wait().context("poll native worker")? {
            break status_chirho;
        }
        if started_chirho.elapsed() > timeout_chirho {
            let _ = child_chirho.kill();
            let _ = child_chirho.wait();
            bail!(
                "native worker timed out after {} ms",
                spec_obj_chirho.timeout_ms_chirho
            );
        }
        thread::sleep(Duration::from_millis(2));
    };
    let output_chirho = join_reader_chirho(stdout_reader_chirho, "stdout")?;
    let stderr_bytes_chirho = join_reader_chirho(stderr_reader_chirho, "stderr")?;
    if output_chirho.len() > spec_obj_chirho.max_output_bytes_chirho {
        bail!(
            "native worker output has {} bytes, over max {}",
            output_chirho.len(),
            spec_obj_chirho.max_output_bytes_chirho
        );
    }
    if !status_chirho.success() {
        return Err(native_worker_status_error_chirho(
            status_chirho,
            &stderr_bytes_chirho,
        ));
    }
    Ok(NativeRunOutcomeChirho {
        output_chirho,
        elapsed_ms_chirho: started_chirho.elapsed().as_millis() as u64,
        sandbox_chirho,
        pooled_chirho: false,
    })
}

fn contextual_native_program_chirho(
    spec_chirho: &NativeProgramSpecChirho,
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<NativeProgramSpecChirho> {
    let Some(context_chirho) = request_context_chirho else {
        return Ok(spec_chirho.clone());
    };
    if spec_chirho.capabilities_chirho.is_empty() {
        return Ok(spec_chirho.clone());
    }
    let mut effective_chirho = spec_chirho.clone();
    effective_chirho.capabilities_chirho = spec_chirho
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
    effective_chirho.capabilities_chirho =
        canonical_capabilities_chirho(&effective_chirho.capabilities_chirho)?;
    Ok(effective_chirho)
}

fn build_native_run_key_chirho(
    spec_obj_chirho: &NativeProgramSpecChirho,
    spec_chirho: &HashChirho,
    input_hash_chirho: &HashChirho,
) -> Result<RunKeyChirho> {
    let mut inputs_chirho = BTreeMap::new();
    inputs_chirho.insert("in".to_string(), input_hash_chirho.clone());
    let caps_hash_chirho = store_chirho::hash_object_chirho(&spec_obj_chirho.capabilities_chirho)?;
    Ok(RunKeyChirho {
        node_chirho: spec_chirho.clone(),
        inputs_chirho,
        caps_chirho: caps_hash_chirho,
    })
}

fn executable_capability_chirho(
    spec_chirho: &NativeProgramSpecChirho,
) -> Result<Option<CapabilityChirho>> {
    let executable_chirho = spec_chirho
        .capabilities_chirho
        .iter()
        .filter(|capability_chirho| !is_context_capability_chirho(capability_chirho))
        .cloned()
        .collect::<Vec<_>>();
    if executable_chirho.len() > 1 {
        bail!("native program specs may declare at most one executable blessed effect capability");
    }
    Ok(executable_chirho.into_iter().next())
}

fn enforce_identity_for_native_effect_chirho(
    spec_chirho: &NativeProgramSpecChirho,
    capability_chirho: &CapabilityChirho,
) -> Result<()> {
    let caller_chirho = match capability_chirho {
        CapabilityChirho::PaidEffectChirho { caller_chirho, .. }
        | CapabilityChirho::QueryChirho { caller_chirho, .. } => caller_chirho,
        _ => return Ok(()),
    };
    let authorized_chirho = spec_chirho
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
            "native effect '{}' requires matching UserIdentityChirho for caller '{}'",
            spec_chirho.name_chirho,
            caller_chirho
        );
    }
    Ok(())
}

fn is_context_capability_chirho(capability_chirho: &CapabilityChirho) -> bool {
    matches!(
        capability_chirho,
        CapabilityChirho::UserIdentityChirho { .. }
            | CapabilityChirho::AppContextChirho { .. }
            | CapabilityChirho::SecretRefChirho { .. }
    )
}

fn materialize_native_executable_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
    spec_obj_chirho: &NativeProgramSpecChirho,
) -> Result<PathBuf> {
    let dir_chirho = root_chirho
        .join("native-workers-chirho")
        .join(&spec_chirho.0);
    std::fs::create_dir_all(&dir_chirho)?;
    let path_chirho = dir_chirho.join("worker-chirho");
    let bytes_chirho = cas_chirho::get_chirho(root_chirho, &spec_obj_chirho.executable_chirho)
        .with_context(|| {
            format!(
                "native executable {} not in CAS",
                spec_obj_chirho.executable_chirho.0
            )
        })?;
    let actual_hash_chirho = cas_chirho::hash_chirho(&bytes_chirho);
    if actual_hash_chirho != spec_obj_chirho.executable_chirho {
        bail!("native executable hash mismatch");
    }
    if !path_chirho.exists() || std::fs::read(&path_chirho)? != bytes_chirho {
        std::fs::write(&path_chirho, &bytes_chirho)?;
    }
    make_executable_chirho(&path_chirho)?;
    Ok(path_chirho)
}

#[cfg(unix)]
fn make_executable_chirho(path_chirho: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions_chirho = std::fs::metadata(path_chirho)?.permissions();
    permissions_chirho.set_mode(0o700);
    std::fs::set_permissions(path_chirho, permissions_chirho)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable_chirho(_path_chirho: &Path) -> Result<()> {
    Ok(())
}

fn cached_with_current_parents_chirho(
    root_chirho: &Path,
    mut cached_chirho: RunResultChirho,
    parents_chirho: &[HashChirho],
    capability_chirho: Option<&CapabilityChirho>,
) -> Result<RunResultChirho> {
    let invoke_response_chirho = if let Some(capability_chirho) = capability_chirho {
        cache_chirho::cached_invoke_response_chirho(root_chirho, &cached_chirho, capability_chirho)?
    } else {
        None
    };
    let invoked_parent_chirho = invoke_response_chirho
        .as_ref()
        .map(|response_chirho| response_chirho.target_run_chirho.clone());
    let expected_parents_chirho =
        cache_chirho::parents_with_invoked_parent_chirho(parents_chirho, invoked_parent_chirho);
    let mut changed_chirho = false;
    if let Some(response_chirho) = invoke_response_chirho {
        if cached_chirho.outputs_chirho.get("out") != Some(&response_chirho.payload_hash_chirho) {
            cached_chirho
                .outputs_chirho
                .insert("out".to_string(), response_chirho.payload_hash_chirho);
            changed_chirho = true;
        }
    }
    if cached_chirho.parents_chirho != expected_parents_chirho {
        cached_chirho.parents_chirho = expected_parents_chirho;
        changed_chirho = true;
    }
    if changed_chirho {
        cache_chirho::store_result_chirho(root_chirho, &cached_chirho)?;
    }
    Ok(cached_chirho)
}
fn read_pipe_chirho(mut pipe_chirho: impl Read) -> Result<Vec<u8>> {
    let mut bytes_chirho = Vec::new();
    pipe_chirho.read_to_end(&mut bytes_chirho)?;
    Ok(bytes_chirho)
}

fn join_reader_chirho(
    handle_chirho: thread::JoinHandle<Result<Vec<u8>>>,
    label_chirho: &str,
) -> Result<Vec<u8>> {
    handle_chirho
        .join()
        .map_err(|_| anyhow!("native worker {label_chirho} reader panicked"))?
}

fn validate_native_program_chirho(spec_chirho: &NativeProgramSpecChirho) -> Result<()> {
    if spec_chirho.schema_chirho != NATIVE_PROGRAM_SCHEMA_CHIRHO {
        bail!(
            "unsupported native program schema '{}'",
            spec_chirho.schema_chirho
        );
    }
    validate_token_chirho("native program name", &spec_chirho.name_chirho)?;
    validate_token_chirho(
        "native program registrar",
        &spec_chirho.registered_by_chirho,
    )?;
    if spec_chirho.registered_pubkey_chirho.len() != 64
        || !spec_chirho
            .registered_pubkey_chirho
            .chars()
            .all(|ch_chirho| ch_chirho.is_ascii_hexdigit())
    {
        bail!("native registrar pubkey must be a 32-byte hex ed25519 public key");
    }
    validate_native_abi_chirho(&spec_chirho.abi_chirho)?;
    if spec_chirho.timeout_ms_chirho == 0 || spec_chirho.timeout_ms_chirho > 300_000 {
        bail!("native timeout must be between 1 and 300000 ms");
    }
    if spec_chirho.max_memory_bytes_chirho < 1024 * 1024
        || spec_chirho.max_memory_bytes_chirho > 16 * 1024 * 1024 * 1024
    {
        bail!("native memory ceiling must be between 1MiB and 16GiB");
    }
    if spec_chirho.max_input_bytes_chirho == 0 || spec_chirho.max_output_bytes_chirho == 0 {
        bail!("native input/output byte ceilings must be nonzero");
    }
    if spec_chirho.max_input_bytes_chirho > 64 * 1024 * 1024
        || spec_chirho.max_output_bytes_chirho > 64 * 1024 * 1024
    {
        bail!("native input/output byte ceilings must be <= 64MiB");
    }
    if spec_chirho.warm_pool_size_chirho > 64 {
        bail!("native warm pool size must be <= 64");
    }
    let canonical_syscalls_chirho =
        canonical_syscalls_chirho(&spec_chirho.allowed_syscalls_chirho)?;
    if canonical_syscalls_chirho != spec_chirho.allowed_syscalls_chirho {
        bail!("native syscalls must be canonical and sorted");
    }
    let canonical_capabilities_chirho =
        canonical_capabilities_chirho(&spec_chirho.capabilities_chirho)?;
    if canonical_capabilities_chirho != spec_chirho.capabilities_chirho {
        bail!("native capabilities must be canonical and sorted");
    }
    for arg_chirho in &spec_chirho.argv_chirho {
        validate_arg_chirho(arg_chirho)?;
    }
    let _ = executable_capability_chirho(spec_chirho)?;
    Ok(())
}

fn native_spec_message_chirho(spec_chirho: &NativeProgramSpecChirho) -> Result<Vec<u8>> {
    let mut unsigned_chirho = spec_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

fn validate_native_abi_chirho(abi_chirho: &str) -> Result<&str> {
    match abi_chirho {
        NATIVE_ABI_BYTES_STDIO_CHIRHO | NATIVE_ABI_BYTES_STDIO_FRAMED_CHIRHO => Ok(abi_chirho),
        _ => bail!("unsupported native ABI '{abi_chirho}'"),
    }
}

fn verify_native_spec_signature_chirho(
    root_chirho: &Path,
    spec_chirho: &NativeProgramSpecChirho,
) -> Result<bool> {
    if spec_chirho.sig_chirho.is_empty() {
        bail!("native program spec is missing its platform admission signature");
    }
    let platform_pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    if spec_chirho.registered_pubkey_chirho != platform_pubkey_chirho {
        bail!("native program spec was not admitted by this cairn instance");
    }
    let message_chirho = native_spec_message_chirho(spec_chirho)?;
    let valid_chirho = signer_chirho::verify_with_pubkey_chirho(
        &spec_chirho.registered_pubkey_chirho,
        &message_chirho,
        &spec_chirho.sig_chirho,
    )?;
    if !valid_chirho {
        bail!("native program spec platform admission signature invalid");
    }
    Ok(true)
}

fn canonical_capabilities_chirho(
    capabilities_chirho: &[CapabilityChirho],
) -> Result<Vec<CapabilityChirho>> {
    let mut encoded_chirho = BTreeSet::new();
    for capability_chirho in capabilities_chirho {
        encoded_chirho.insert(serde_json::to_string(capability_chirho)?);
    }
    encoded_chirho
        .into_iter()
        .map(|capability_chirho| Ok(serde_json::from_str(&capability_chirho)?))
        .collect()
}

fn canonical_tokens_chirho(label_chirho: &str, values_chirho: &[String]) -> Result<Vec<String>> {
    if values_chirho.is_empty() {
        bail!("{label_chirho} list must not be empty");
    }
    let mut out_chirho = BTreeSet::new();
    for value_chirho in values_chirho {
        out_chirho.insert(validate_token_chirho(label_chirho, value_chirho)?);
    }
    Ok(out_chirho.into_iter().collect())
}

fn canonical_syscalls_chirho(values_chirho: &[String]) -> Result<Vec<String>> {
    let canonical_chirho = canonical_tokens_chirho("syscall", values_chirho)?;
    for syscall_chirho in &canonical_chirho {
        if nondeterministic_native_syscall_chirho(syscall_chirho) {
            bail!(
                "native syscall '{syscall_chirho}' is nondeterministic or opens unmediated I/O; route it through a blessed effect instead"
            );
        }
        if !known_native_syscall_chirho(syscall_chirho) {
            bail!("unknown native syscall '{syscall_chirho}'");
        }
    }
    Ok(canonical_chirho)
}

fn nondeterministic_native_syscall_chirho(syscall_chirho: &str) -> bool {
    matches!(
        syscall_chirho,
        "clock_gettime"
            | "gettimeofday"
            | "time"
            | "getrandom"
            | "open"
            | "openat"
            | "creat"
            | "socket"
            | "connect"
            | "accept"
            | "accept4"
            | "sendto"
            | "recvfrom"
    )
}

fn known_native_syscall_chirho(syscall_chirho: &str) -> bool {
    matches!(
        syscall_chirho,
        "read"
            | "write"
            | "exit"
            | "exit_group"
            | "brk"
            | "execve"
            | "mmap"
            | "mprotect"
            | "munmap"
            | "rt_sigreturn"
            | "rt_sigaction"
            | "rt_sigprocmask"
            | "futex"
            | "set_tid_address"
            | "set_robust_list"
            | "rseq"
            | "arch_prctl"
            | "close"
    )
}

fn validate_token_chirho(label_chirho: &str, value_chirho: &str) -> Result<String> {
    let value_chirho = value_chirho.trim();
    if value_chirho.is_empty()
        || value_chirho.len() > 128
        || !value_chirho.chars().all(|ch_chirho| {
            ch_chirho.is_ascii_alphanumeric() || matches!(ch_chirho, '-' | '_' | '.' | '/' | ':')
        })
    {
        bail!("{label_chirho} must be a short safe token");
    }
    Ok(value_chirho.to_string())
}

fn validate_arg_chirho(value_chirho: &str) -> Result<String> {
    if value_chirho.is_empty()
        || value_chirho.len() > 256
        || value_chirho.contains('\0')
        || value_chirho.contains('\n')
    {
        bail!("native worker argv entries must be nonempty single-line strings");
    }
    Ok(value_chirho.to_string())
}

pub fn sandbox_status_chirho(spec_chirho: &NativeProgramSpecChirho) -> NativeSandboxStatusChirho {
    platform_sandbox_status_chirho(spec_chirho)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn platform_sandbox_status_chirho(
    _spec_chirho: &NativeProgramSpecChirho,
) -> NativeSandboxStatusChirho {
    NativeSandboxStatusChirho {
        platform_chirho: "linux-x86_64".to_string(),
        seccomp_enforced_chirho: true,
        reason_chirho: "seccomp-bpf available".to_string(),
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn platform_sandbox_status_chirho(
    _spec_chirho: &NativeProgramSpecChirho,
) -> NativeSandboxStatusChirho {
    NativeSandboxStatusChirho {
        platform_chirho: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        seccomp_enforced_chirho: false,
        reason_chirho: "Linux x86_64 seccomp-bpf is not available on this platform".to_string(),
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn apply_pre_exec_sandbox_chirho(
    command_chirho: &mut Command,
    spec_chirho: &NativeProgramSpecChirho,
) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let allowed_syscalls_chirho = spec_chirho.allowed_syscalls_chirho.clone();
    let max_memory_bytes_chirho = spec_chirho.max_memory_bytes_chirho;
    unsafe {
        command_chirho.pre_exec(move || {
            apply_memory_limit_chirho(max_memory_bytes_chirho)?;
            install_seccomp_chirho(&allowed_syscalls_chirho).map_err(std::io::Error::other)
        });
    }
    Ok(())
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn apply_pre_exec_sandbox_chirho(
    _command_chirho: &mut Command,
    _spec_chirho: &NativeProgramSpecChirho,
) -> Result<()> {
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn apply_memory_limit_chirho(max_memory_bytes_chirho: u64) -> std::io::Result<()> {
    let limit_chirho = libc::rlimit {
        rlim_cur: max_memory_bytes_chirho as libc::rlim_t,
        rlim_max: max_memory_bytes_chirho as libc::rlim_t,
    };
    unsafe {
        if libc::setrlimit(libc::RLIMIT_AS, &limit_chirho as *const libc::rlimit) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn install_seccomp_chirho(allowed_syscalls_chirho: &[String]) -> std::io::Result<()> {
    const AUDIT_ARCH_X86_64_CHIRHO: u32 = 0xC000_003E;
    let mut filters_chirho = vec![
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 4,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 1,
            jf: 0,
            k: AUDIT_ARCH_X86_64_CHIRHO,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_KILL_PROCESS,
        },
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ];
    for syscall_chirho in allowed_syscalls_chirho {
        let nr_chirho = syscall_number_chirho(syscall_chirho).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unknown syscall {syscall_chirho}"),
            )
        })?;
        filters_chirho.push(libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: nr_chirho as u32,
        });
        filters_chirho.push(libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        });
    }
    filters_chirho.push(libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_KILL_PROCESS,
    });
    let mut program_chirho = libc::sock_fprog {
        len: filters_chirho.len() as u16,
        filter: filters_chirho.as_mut_ptr(),
    };
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &mut program_chirho as *mut libc::sock_fprog,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn syscall_number_chirho(name_chirho: &str) -> Option<i64> {
    Some(match name_chirho {
        "read" => libc::SYS_read,
        "write" => libc::SYS_write,
        "exit" => libc::SYS_exit,
        "exit_group" => libc::SYS_exit_group,
        "brk" => libc::SYS_brk,
        "mmap" => libc::SYS_mmap,
        "mprotect" => libc::SYS_mprotect,
        "munmap" => libc::SYS_munmap,
        "rt_sigreturn" => libc::SYS_rt_sigreturn,
        "rt_sigaction" => libc::SYS_rt_sigaction,
        "rt_sigprocmask" => libc::SYS_rt_sigprocmask,
        "futex" => libc::SYS_futex,
        "set_tid_address" => libc::SYS_set_tid_address,
        "set_robust_list" => libc::SYS_set_robust_list,
        "rseq" => libc::SYS_rseq,
        "arch_prctl" => libc::SYS_arch_prctl,
        "close" => libc::SYS_close,
        "execve" => libc::SYS_execve,
        _ => return None,
    })
}

fn native_worker_status_error_chirho(
    status_chirho: ExitStatus,
    stderr_bytes_chirho: &[u8],
) -> anyhow::Error {
    let stderr_chirho = String::from_utf8_lossy(stderr_bytes_chirho);
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal_chirho) = status_chirho.signal() {
            return anyhow!(
                "native worker killed by signal {signal_chirho}; status={status_chirho}; stderr={stderr_chirho}"
            );
        }
    }
    anyhow!("native worker exited with {status_chirho}; stderr={stderr_chirho}")
}

#[cfg(test)]
#[path = "native_worker_chirho/tests_chirho.rs"]
mod tests_chirho;
