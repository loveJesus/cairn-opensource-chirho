// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Signed DAG run-intent admission records for the serve path.

use crate::model_chirho::{DagChirho, HashChirho, RequestContextChirho};
use crate::{app_chirho, cas_chirho, dag_chirho, oauth_chirho, seqlog_chirho, store_chirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_signer_chirho::signer_chirho;
use cairn_write_relay_chirho::{CallerIdempotencyKeyChirho, CallerOperationBindingChirho};
use dag_chirho::refusal_chirho::{
    dag_execution_refusal_observation_chirho, wrap_dag_execution_attempt_chirho,
    wrap_dag_execution_stage_chirho, DagExecutionAttemptOrdinalChirho,
    DagExecutionRefusalIdentityChirho,
};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "run_intent_chirho/record_verify_chirho.rs"]
mod record_verify_chirho;
pub use record_verify_chirho::verify_run_intent_records_chirho;
#[path = "run_intent_chirho/admission_view_chirho.rs"]
mod admission_view_chirho;
#[path = "run_intent_chirho/durable_admission_chirho/mod.rs"]
pub mod durable_admission_chirho;
#[path = "run_intent_chirho/resume_chirho.rs"]
mod resume_chirho;
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
pub use admission_view_chirho::run_intent_view_metrics_chirho;
pub use admission_view_chirho::{
    spawn_run_intent_view_warm_up_chirho, warm_run_intent_view_chirho,
};
pub use resume_chirho::{
    resume_request_context_chirho, resume_unfinished_run_intents_chirho,
    resume_unfinished_run_intents_with_effect_runtime_chirho,
    resume_unfinished_run_intents_with_projection_read_chirho,
};

pub const RUN_INTENT_RECORD_SCHEMA_CHIRHO: &str = "run-intent-record-v1-chirho";
pub const RUN_INTENT_RECORD_SCHEMA_V2_CHIRHO: &str = "run-intent-record-v2-chirho";
pub const RUN_INTENT_RECORD_SCHEMA_V3_CHIRHO: &str = "run-intent-record-v3-chirho";
const RUN_INTENT_PENDING_CHIRHO: &str = "pending-chirho";
const RUN_INTENT_RUNNING_CHIRHO: &str = "running-chirho";
const RUN_INTENT_DONE_CHIRHO: &str = "done-chirho";
const RUN_INTENT_FAILED_CHIRHO: &str = "failed-chirho";
/// A run that refused before any side effect, so an identical retry runs it again (the pre-effect brick, shape (B),
/// agy #25885). THIS RELEASE READS IT AND NEVER WRITES IT (agy #25907): readers ship one release before writers, so a
/// rollback to the previous binary always lands on one that can fold the log. `RunIntentWriteStatusChirho` keeps the
/// write out of the append door's reach.
const RUN_INTENT_ABORTED_CHIRHO: &str = "aborted-chirho";
const RUN_INTENT_SCOPE_INDEX_CONTEXT_CHIRHO: &str = "cairn-run-intent-scope-index-v1-chirho";

thread_local! {
    static RUN_INTENT_EXECUTION_CHIRHO: RefCell<Option<RunIntentExecutionContextChirho>> = const { RefCell::new(None) };
    static RUN_INTENT_EFFECT_INVOCATION_CHIRHO: RefCell<Option<RunIntentEffectInvocationChirho>> = const { RefCell::new(None) };
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunIntentScopeChirho {
    pub kind_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_hash_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_principal_hash_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_principal_hash_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id_hash_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_hash_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_book_chirho: Option<HashChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_policy_chirho: Option<HashChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunIntentRecordChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub run_chirho: HashChirho,
    pub dag_chirho: HashChirho,
    pub request_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_private_subject_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_idempotency_key_digest_chirho: Option<HashChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_operation_digest_chirho: Option<HashChirho>,
    pub idempotency_context_hash_chirho: HashChirho,
    pub scope_chirho: RunIntentScopeChirho,
    pub status_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_kind_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_digest_chirho: Option<HashChirho>,
    pub at_ms_chirho: u128,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunIntentSubjectIndexHashesChirho {
    pub user_principal_hash_chirho: String,
    pub owner_principal_hash_chirho: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunIntentResumeReportChirho {
    pub records_chirho: usize,
    pub unfinished_chirho: usize,
    pub resumed_chirho: usize,
    pub failed_chirho: usize,
}

#[derive(Serialize)]
struct RunIntentIdempotencyContextChirho {
    schema_chirho: String,
    dag_chirho: HashChirho,
    request_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    caller_idempotency_key_digest_chirho: Option<HashChirho>,
    scope_chirho: RunIntentScopeChirho,
}

#[derive(Serialize)]
struct KeyedRunIntentIdempotencyContextChirho {
    schema_chirho: String,
    dag_chirho: HashChirho,
    request_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_private_subject_chirho: Option<String>,
    caller_idempotency_key_digest_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    caller_operation_digest_chirho: Option<HashChirho>,
    caller_scope_chirho: RunIntentCallerScopeChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RunIntentCallerScopeChirho {
    kind_chirho: String,
    app_hash_chirho: Option<String>,
    user_principal_hash_chirho: Option<String>,
}

#[derive(Serialize)]
struct RunIntentRunIdentityChirho {
    schema_chirho: String,
    idempotency_context_hash_chirho: HashChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RunIntentExecutionContextChirho {
    run_chirho: HashChirho,
    mode_chirho: RunIntentExecutionModeChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RunIntentEffectInvocationIdentityChirho {
    schema_chirho: String,
    run_chirho: HashChirho,
    node_chirho: HashChirho,
    effect_step_chirho: u32,
}

/// Engine-derived logical effect identity for the active run-intent execution.
///
/// Descriptor-D uses this coordinate to atomically create-or-load one exact signed intent line.
/// The per-root run lock is a liveness aid; this durable coordinate remains the money floor when a
/// hosted composition introduces processes or storage outside that lock domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RunIntentEffectInvocationChirho {
    pub run_chirho: HashChirho,
    pub node_chirho: HashChirho,
    pub effect_step_chirho: u32,
    pub invocation_ref_chirho: HashChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunIntentExecutionModeChirho {
    FreshChirho,
    ResumeChirho,
    CompletedReplayChirho,
}

impl RunIntentExecutionModeChirho {
    fn suppresses_cached_billing_chirho(self) -> bool {
        matches!(self, Self::ResumeChirho | Self::CompletedReplayChirho)
    }

    fn replays_volatile_effects_chirho(self) -> bool {
        matches!(self, Self::ResumeChirho)
    }

    fn records_terminal_chirho(self) -> bool {
        !matches!(self, Self::CompletedReplayChirho)
    }

    fn attempt_ordinal_chirho(self) -> DagExecutionAttemptOrdinalChirho {
        match self {
            Self::FreshChirho => DagExecutionAttemptOrdinalChirho::FirstChirho,
            Self::ResumeChirho => DagExecutionAttemptOrdinalChirho::ResumeChirho,
            Self::CompletedReplayChirho => DagExecutionAttemptOrdinalChirho::CompletedReplayChirho,
        }
    }
}

#[cfg(test)]
pub(crate) fn with_run_intent_execution_chirho<T>(
    run_chirho: &HashChirho,
    replay_chirho: bool,
    f_chirho: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let mode_chirho = if replay_chirho {
        RunIntentExecutionModeChirho::ResumeChirho
    } else {
        RunIntentExecutionModeChirho::FreshChirho
    };
    with_run_intent_execution_mode_chirho(run_chirho, mode_chirho, f_chirho)
}

fn with_run_intent_execution_mode_chirho<T>(
    run_chirho: &HashChirho,
    mode_chirho: RunIntentExecutionModeChirho,
    f_chirho: impl FnOnce() -> Result<T>,
) -> Result<T> {
    RUN_INTENT_EXECUTION_CHIRHO.with(|slot_chirho| {
        let previous_chirho = slot_chirho.replace(Some(RunIntentExecutionContextChirho {
            run_chirho: run_chirho.clone(),
            mode_chirho,
        }));
        let result_chirho = f_chirho();
        slot_chirho.replace(previous_chirho);
        result_chirho
    })
}

/// Crash resumes and completed retries both reuse the original money coordinate, so neither may
/// enter a generic cache-billing road a second time.
pub(crate) fn run_intent_cached_billing_suppressed_chirho() -> bool {
    RUN_INTENT_EXECUTION_CHIRHO.with(|slot_chirho| {
        slot_chirho.borrow().as_ref().is_some_and(|context_chirho| {
            context_chirho
                .mode_chirho
                .suppresses_cached_billing_chirho()
        })
    })
}

/// Only an unfinished crash resume replays its recorded volatile observation. A completed request
/// submitted again is a new read of current state even though its effect coordinate remains stable.
pub(crate) fn run_intent_volatile_replay_active_chirho() -> bool {
    RUN_INTENT_EXECUTION_CHIRHO.with(|slot_chirho| {
        slot_chirho.borrow().as_ref().is_some_and(|context_chirho| {
            context_chirho.mode_chirho.replays_volatile_effects_chirho()
        })
    })
}

pub(crate) fn with_run_intent_effect_invocation_chirho<T>(
    node_chirho: &HashChirho,
    effect_step_chirho: u32,
    f_chirho: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let execution_chirho =
        RUN_INTENT_EXECUTION_CHIRHO.with(|slot_chirho| slot_chirho.borrow().clone());
    let Some(execution_chirho) = execution_chirho else {
        return f_chirho();
    };
    let invocation_ref_chirho =
        store_chirho::hash_object_chirho(&RunIntentEffectInvocationIdentityChirho {
            schema_chirho: "run-intent-effect-invocation-v1-chirho".to_string(),
            run_chirho: execution_chirho.run_chirho.clone(),
            node_chirho: node_chirho.clone(),
            effect_step_chirho,
        })?;
    RUN_INTENT_EFFECT_INVOCATION_CHIRHO.with(|slot_chirho| {
        let previous_chirho = slot_chirho.replace(Some(RunIntentEffectInvocationChirho {
            run_chirho: execution_chirho.run_chirho,
            node_chirho: node_chirho.clone(),
            effect_step_chirho,
            invocation_ref_chirho,
        }));
        let result_chirho = f_chirho();
        slot_chirho.replace(previous_chirho);
        result_chirho
    })
}

pub(crate) fn current_run_intent_effect_invocation_chirho(
) -> Option<RunIntentEffectInvocationChirho> {
    RUN_INTENT_EFFECT_INVOCATION_CHIRHO.with(|slot_chirho| slot_chirho.borrow().clone())
}

pub fn run_intent_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("run-intents-chirho.jsonl")
}

pub fn load_run_intent_records_chirho(root_chirho: &Path) -> Result<Vec<RunIntentRecordChirho>> {
    let path_chirho = run_intent_records_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .map(|line_chirho| serde_json::from_str(line_chirho).context("decode run intent record"))
        .collect()
}

pub fn run_dag_with_intent_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<dag_chirho::DagRunReportChirho> {
    run_dag_with_intent_and_projection_read_chirho(
        root_chirho,
        dag_hash_chirho,
        input_chirho,
        request_context_chirho,
        None,
    )
}

/// Run one public-input DAG with a caller-supplied logical-operation key.
///
/// Part of
/// `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/serve-write-forwarding-design-chirho.md`.
/// The raw caller key is never persisted; only its domain-separated digest enters the durable
/// run-intent identity.
pub fn run_dag_with_intent_and_caller_key_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    caller_idempotency_key_chirho: &CallerIdempotencyKeyChirho,
) -> Result<dag_chirho::DagRunReportChirho> {
    run_dag_with_intent_and_projection_read_and_caller_key_chirho(
        root_chirho,
        dag_hash_chirho,
        input_chirho,
        request_context_chirho,
        None,
        caller_idempotency_key_chirho,
    )
}

pub fn run_dag_with_intent_and_projection_read_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    projection_read_chirho: Option<
        &dyn super::projection_read_chirho::PublishedProjectionReadPortChirho,
    >,
) -> Result<dag_chirho::DagRunReportChirho> {
    run_dag_with_intent_and_effect_runtime_chirho(
        root_chirho,
        dag_hash_chirho,
        input_chirho,
        request_context_chirho,
        super::DagEffectRuntimePortsChirho {
            projection_read_chirho,
            postgres_reversible_chirho: None,
            llm_served_chirho: None,
            private_attribution_chirho: None,
        },
    )
}

pub fn run_dag_with_intent_and_projection_read_and_caller_key_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    projection_read_chirho: Option<
        &dyn super::projection_read_chirho::PublishedProjectionReadPortChirho,
    >,
    caller_idempotency_key_chirho: &CallerIdempotencyKeyChirho,
) -> Result<dag_chirho::DagRunReportChirho> {
    run_dag_with_intent_and_effect_runtime_and_caller_key_chirho(
        root_chirho,
        dag_hash_chirho,
        input_chirho,
        request_context_chirho,
        super::DagEffectRuntimePortsChirho {
            projection_read_chirho,
            postgres_reversible_chirho: None,
            llm_served_chirho: None,
            private_attribution_chirho: None,
        },
        caller_idempotency_key_chirho,
    )
}

pub fn run_dag_with_intent_and_effect_runtime_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    runtime_ports_chirho: super::DagEffectRuntimePortsChirho<'_>,
) -> Result<dag_chirho::DagRunReportChirho> {
    run_dag_with_intent_and_effect_runtime_optional_caller_key_chirho(
        root_chirho,
        dag_hash_chirho,
        input_chirho,
        request_context_chirho,
        runtime_ports_chirho,
        None,
        None,
    )
}

pub fn run_dag_with_intent_and_effect_runtime_and_caller_key_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    runtime_ports_chirho: super::DagEffectRuntimePortsChirho<'_>,
    caller_idempotency_key_chirho: &CallerIdempotencyKeyChirho,
) -> Result<dag_chirho::DagRunReportChirho> {
    run_dag_with_intent_and_effect_runtime_optional_caller_key_chirho(
        root_chirho,
        dag_hash_chirho,
        input_chirho,
        request_context_chirho,
        runtime_ports_chirho,
        Some(caller_idempotency_key_chirho),
        None,
    )
}

/// Run one served public-input DAG with the durable caller key bound to its exact HTTP operation.
pub fn run_dag_with_intent_and_effect_runtime_and_caller_operation_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    runtime_ports_chirho: super::DagEffectRuntimePortsChirho<'_>,
    caller_idempotency_key_chirho: &CallerIdempotencyKeyChirho,
    caller_operation_chirho: &CallerOperationBindingChirho,
) -> Result<dag_chirho::DagRunReportChirho> {
    run_dag_with_intent_and_effect_runtime_optional_caller_key_chirho(
        root_chirho,
        dag_hash_chirho,
        input_chirho,
        request_context_chirho,
        runtime_ports_chirho,
        Some(caller_idempotency_key_chirho),
        Some(caller_operation_chirho),
    )
}

fn run_dag_with_intent_and_effect_runtime_optional_caller_key_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    runtime_ports_chirho: super::DagEffectRuntimePortsChirho<'_>,
    caller_idempotency_key_chirho: Option<&CallerIdempotencyKeyChirho>,
    caller_operation_chirho: Option<&CallerOperationBindingChirho>,
) -> Result<dag_chirho::DagRunReportChirho> {
    if caller_operation_chirho.is_some() && caller_idempotency_key_chirho.is_none() {
        bail!("caller operation binding requires a caller idempotency key");
    }
    let dag_chirho: DagChirho = store_chirho::get_object_chirho(root_chirho, dag_hash_chirho)?;
    let request_chirho = if caller_idempotency_key_chirho.is_some() {
        cas_chirho::hash_chirho(input_chirho)
    } else {
        cas_chirho::add_chirho(root_chirho, input_chirho)?
    };
    let scope_chirho = run_intent_scope_chirho(root_chirho, request_context_chirho)?;
    let caller_idempotency_key_digest_chirho =
        caller_idempotency_key_chirho.map(caller_idempotency_key_digest_chirho);
    let caller_operation_digest_chirho =
        caller_operation_chirho.map(caller_operation_digest_chirho);
    let idempotency_context_hash_chirho = run_intent_context_hash_from_digest_chirho(
        dag_hash_chirho,
        &request_chirho,
        &scope_chirho,
        None,
        caller_idempotency_key_digest_chirho.as_ref(),
        caller_operation_digest_chirho.as_ref(),
    )?;
    let run_chirho = run_intent_run_hash_chirho(&idempotency_context_hash_chirho)?;
    let admission_chirho = RunIntentAdmissionChirho {
        run_chirho,
        dag_chirho: dag_hash_chirho.clone(),
        request_chirho,
        request_private_subject_chirho: None,
        caller_idempotency_key_digest_chirho,
        caller_operation_digest_chirho,
        idempotency_context_hash_chirho,
        scope_chirho,
    };
    run_prepared_dag_with_intent_chirho(
        root_chirho,
        &dag_chirho,
        dag_chirho::DagInputValueChirho::PublicBytesChirho(input_chirho.to_vec()),
        request_context_chirho,
        &admission_chirho,
        runtime_ports_chirho,
    )
}

pub fn run_dag_with_private_input_intent_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    subject_chirho: &str,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<dag_chirho::DagRunReportChirho> {
    run_dag_with_private_input_intent_and_projection_read_chirho(
        root_chirho,
        dag_hash_chirho,
        subject_chirho,
        input_chirho,
        request_context_chirho,
        None,
    )
}

pub fn run_dag_with_private_input_intent_and_caller_key_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    subject_chirho: &str,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    caller_idempotency_key_chirho: &CallerIdempotencyKeyChirho,
) -> Result<dag_chirho::DagRunReportChirho> {
    run_dag_with_private_input_intent_and_projection_read_and_caller_key_chirho(
        root_chirho,
        dag_hash_chirho,
        subject_chirho,
        input_chirho,
        request_context_chirho,
        None,
        caller_idempotency_key_chirho,
    )
}

pub fn run_dag_with_private_input_intent_and_projection_read_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    subject_chirho: &str,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    projection_read_chirho: Option<
        &dyn super::projection_read_chirho::PublishedProjectionReadPortChirho,
    >,
) -> Result<dag_chirho::DagRunReportChirho> {
    run_dag_with_private_input_intent_and_effect_runtime_chirho(
        root_chirho,
        dag_hash_chirho,
        subject_chirho,
        input_chirho,
        request_context_chirho,
        super::DagEffectRuntimePortsChirho {
            projection_read_chirho,
            postgres_reversible_chirho: None,
            llm_served_chirho: None,
            private_attribution_chirho: None,
        },
    )
}

pub fn run_dag_with_private_input_intent_and_projection_read_and_caller_key_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    subject_chirho: &str,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    projection_read_chirho: Option<
        &dyn super::projection_read_chirho::PublishedProjectionReadPortChirho,
    >,
    caller_idempotency_key_chirho: &CallerIdempotencyKeyChirho,
) -> Result<dag_chirho::DagRunReportChirho> {
    run_dag_with_private_input_intent_and_effect_runtime_and_caller_key_chirho(
        root_chirho,
        dag_hash_chirho,
        subject_chirho,
        input_chirho,
        request_context_chirho,
        super::DagEffectRuntimePortsChirho {
            projection_read_chirho,
            postgres_reversible_chirho: None,
            llm_served_chirho: None,
            private_attribution_chirho: None,
        },
        caller_idempotency_key_chirho,
    )
}

pub fn run_dag_with_private_input_intent_and_effect_runtime_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    subject_chirho: &str,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    runtime_ports_chirho: super::DagEffectRuntimePortsChirho<'_>,
) -> Result<dag_chirho::DagRunReportChirho> {
    run_dag_with_private_input_intent_and_effect_runtime_optional_caller_key_chirho(
        root_chirho,
        dag_hash_chirho,
        subject_chirho,
        input_chirho,
        request_context_chirho,
        runtime_ports_chirho,
        None,
        None,
    )
}

pub fn run_dag_with_private_input_intent_and_effect_runtime_and_caller_key_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    subject_chirho: &str,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    runtime_ports_chirho: super::DagEffectRuntimePortsChirho<'_>,
    caller_idempotency_key_chirho: &CallerIdempotencyKeyChirho,
) -> Result<dag_chirho::DagRunReportChirho> {
    run_dag_with_private_input_intent_and_effect_runtime_optional_caller_key_chirho(
        root_chirho,
        dag_hash_chirho,
        subject_chirho,
        input_chirho,
        request_context_chirho,
        runtime_ports_chirho,
        Some(caller_idempotency_key_chirho),
        None,
    )
}

/// Run one served private-input DAG with the durable caller key bound to its exact HTTP operation.
#[allow(
    clippy::too_many_arguments,
    reason = "the served run binds one complete DAG, privacy, runtime, and caller-operation context"
)]
pub fn run_dag_with_private_input_intent_and_effect_runtime_and_caller_operation_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    subject_chirho: &str,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    runtime_ports_chirho: super::DagEffectRuntimePortsChirho<'_>,
    caller_idempotency_key_chirho: &CallerIdempotencyKeyChirho,
    caller_operation_chirho: &CallerOperationBindingChirho,
) -> Result<dag_chirho::DagRunReportChirho> {
    run_dag_with_private_input_intent_and_effect_runtime_optional_caller_key_chirho(
        root_chirho,
        dag_hash_chirho,
        subject_chirho,
        input_chirho,
        request_context_chirho,
        runtime_ports_chirho,
        Some(caller_idempotency_key_chirho),
        Some(caller_operation_chirho),
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the shared runner receives one complete DAG, privacy, runtime, and caller context"
)]
fn run_dag_with_private_input_intent_and_effect_runtime_optional_caller_key_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    subject_chirho: &str,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    runtime_ports_chirho: super::DagEffectRuntimePortsChirho<'_>,
    caller_idempotency_key_chirho: Option<&CallerIdempotencyKeyChirho>,
    caller_operation_chirho: Option<&CallerOperationBindingChirho>,
) -> Result<dag_chirho::DagRunReportChirho> {
    if caller_operation_chirho.is_some() && caller_idempotency_key_chirho.is_none() {
        bail!("caller operation binding requires a caller idempotency key");
    }
    crate::privacy_chirho::validate_privacy_subject_chirho(subject_chirho)?;
    let dag_chirho: DagChirho = store_chirho::get_object_chirho(root_chirho, dag_hash_chirho)?;
    let request_chirho = cas_chirho::hash_chirho(input_chirho);
    let scope_chirho = run_intent_scope_chirho(root_chirho, request_context_chirho)?;
    // THE PIN (CAIRN #25777; agy #25780, #25781, #25887; scope UNKEYED ONLY, agy #25885). An unkeyed run's v1 context
    // hash omits its private subject, so its run id binds the subject only through the scope's user principal. Two
    // subjects sending the same bytes under one scope would share a run id, and the second would replay the first
    // person's result. So an unkeyed private run whose scope does not name its own subject as that principal (a scope
    // naming none included) is refused here, before any value is stored or any record appended. A keyed run binds its
    // subject in its v2/v3 context hash, so it is not pinned.
    if caller_idempotency_key_chirho.is_none()
        && scope_chirho.user_principal_hash_chirho.as_deref()
            != Some(
                scope_value_hash_chirho(root_chirho, "user_principal_hash_chirho", subject_chirho)?
                    .as_str(),
            )
    {
        bail!(
            "PrivateRunSubjectNotScopePrincipalChirho: an unkeyed private run's subject must be its scope's user \
             principal"
        );
    }
    let caller_idempotency_key_digest_chirho =
        caller_idempotency_key_chirho.map(caller_idempotency_key_digest_chirho);
    let caller_operation_digest_chirho =
        caller_operation_chirho.map(caller_operation_digest_chirho);
    let idempotency_context_hash_chirho = run_intent_context_hash_from_digest_chirho(
        dag_hash_chirho,
        &request_chirho,
        &scope_chirho,
        Some(subject_chirho),
        caller_idempotency_key_digest_chirho.as_ref(),
        caller_operation_digest_chirho.as_ref(),
    )?;
    let run_chirho = run_intent_run_hash_chirho(&idempotency_context_hash_chirho)?;
    let admission_chirho = RunIntentAdmissionChirho {
        run_chirho,
        dag_chirho: dag_hash_chirho.clone(),
        request_chirho,
        request_private_subject_chirho: Some(subject_chirho.to_string()),
        caller_idempotency_key_digest_chirho,
        caller_operation_digest_chirho,
        idempotency_context_hash_chirho,
        scope_chirho,
    };
    run_prepared_dag_with_intent_chirho(
        root_chirho,
        &dag_chirho,
        dag_chirho::DagInputValueChirho::PrivateBytesChirho {
            subject_chirho: subject_chirho.to_string(),
            bytes_chirho: input_chirho.to_vec(),
        },
        request_context_chirho,
        &admission_chirho,
        runtime_ports_chirho,
    )
}

fn run_prepared_dag_with_intent_chirho(
    root_chirho: &Path,
    dag_chirho: &DagChirho,
    input_chirho: dag_chirho::DagInputValueChirho,
    request_context_chirho: Option<&RequestContextChirho>,
    admission_chirho: &RunIntentAdmissionChirho,
    runtime_ports_chirho: super::DagEffectRuntimePortsChirho<'_>,
) -> Result<dag_chirho::DagRunReportChirho> {
    let lock_name_chirho = run_intent_execution_lock_name_chirho(admission_chirho);
    seqlog_chirho::with_named_lock_chirho(root_chirho, &lock_name_chirho, || {
        let latest_chirho =
            latest_verified_run_intent_record_for_admission_chirho(root_chirho, admission_chirho)?;
        let mode_chirho = match latest_chirho {
            None => {
                persist_deferred_public_request_chirho(
                    root_chirho,
                    &input_chirho,
                    admission_chirho,
                )?;
                persist_request_before_admission_chirho(
                    root_chirho,
                    &input_chirho,
                    admission_chirho,
                    &crate::dag_private_value_chirho::RunAttributionSourceChirho::new_chirho(
                        request_context_chirho,
                        runtime_ports_chirho.private_attribution_chirho,
                    ),
                )?;
                append_run_intent_record_chirho(
                    root_chirho,
                    admission_chirho,
                    RunIntentWriteStatusChirho::PendingChirho,
                    None,
                )?;
                append_run_intent_record_chirho(
                    root_chirho,
                    admission_chirho,
                    RunIntentWriteStatusChirho::RunningChirho,
                    None,
                )?;
                RunIntentExecutionModeChirho::FreshChirho
            }
            Some(record_chirho) => {
                if !run_intent_admission_matches_chirho(
                    &run_intent_admission_from_record_chirho(&record_chirho),
                    admission_chirho,
                ) {
                    bail!(
                        "run intent {} collides with different request evidence",
                        admission_chirho.run_chirho.0
                    );
                }
                match record_chirho.status_chirho.as_str() {
                    // A pending run, and an aborted one (it refused before any side effect), runs again: RUNNING is
                    // appended and the run RESUMES, so an effect that a wrongly classified run did complete is
                    // replayed by its idempotency key, never run twice (agy #25907).
                    RUN_INTENT_PENDING_CHIRHO | RUN_INTENT_ABORTED_CHIRHO => {
                        append_run_intent_record_chirho(
                            root_chirho,
                            admission_chirho,
                            RunIntentWriteStatusChirho::RunningChirho,
                            None,
                        )?;
                        RunIntentExecutionModeChirho::ResumeChirho
                    }
                    RUN_INTENT_RUNNING_CHIRHO => RunIntentExecutionModeChirho::ResumeChirho,
                    RUN_INTENT_DONE_CHIRHO => RunIntentExecutionModeChirho::CompletedReplayChirho,
                    RUN_INTENT_FAILED_CHIRHO => {
                        let prior_identity_chirho = record_chirho
                            .error_kind_chirho
                            .as_deref()
                            .and_then(DagExecutionRefusalIdentityChirho::from_str_chirho);
                        let source_chirho = wrap_dag_execution_stage_chirho(
                            DagExecutionRefusalIdentityChirho::RunIntentPreviouslyFailedRefusedChirho,
                            anyhow!(
                                "run intent {} previously failed and requires manual review",
                                admission_chirho.run_chirho.0
                            ),
                        );
                        return Err(wrap_dag_execution_attempt_chirho(
                            source_chirho,
                            DagExecutionAttemptOrdinalChirho::FailedReplayChirho,
                            prior_identity_chirho,
                        ));
                    }
                    status_chirho => bail!(
                        "run intent {} has unsupported latest status {}",
                        admission_chirho.run_chirho.0,
                        status_chirho
                    ),
                }
            }
        };
        run_admitted_dag_chirho(
            root_chirho,
            dag_chirho,
            input_chirho,
            request_context_chirho,
            admission_chirho,
            mode_chirho,
            runtime_ports_chirho,
        )
    })
}

/// Store the run's request value BEFORE its pending record exists, so no admission ever verifies a record whose request
/// value is not stored yet. Every admission verifies every record, and the DAG run stores its input only after the
/// admission has appended. So a concurrent admission met an in-flight record ("private request value missing") and was
/// refused: PFE measured about a quarter of simultaneous saves by two principals refused (#25853), traced in CAIRN
/// #25859. Only a Fresh admission reaches here, so a refused or replayed request stores nothing.
fn persist_request_before_admission_chirho(
    root_chirho: &Path,
    input_chirho: &dag_chirho::DagInputValueChirho,
    admission_chirho: &RunIntentAdmissionChirho,
    attribution_source_chirho: &crate::dag_private_value_chirho::RunAttributionSourceChirho<'_>,
) -> Result<()> {
    let stored_chirho = match input_chirho {
        dag_chirho::DagInputValueChirho::PublicBytesChirho(bytes_chirho) => {
            cas_chirho::add_chirho(root_chirho, bytes_chirho)?
        }
        dag_chirho::DagInputValueChirho::PrivateBytesChirho {
            subject_chirho,
            bytes_chirho,
        } => {
            if admission_chirho.request_private_subject_chirho.as_deref()
                != Some(subject_chirho.as_str())
            {
                bail!("run-intent admission's private subject differs from its private input's subject");
            }
            crate::dag_private_value_chirho::store_dag_value_with_policy_chirho(
                root_chirho,
                bytes_chirho,
                // An admitted private request is the request user's own input.
                &crate::dag_private_value_chirho::ValueStoragePolicyChirho::PrivateBlobRefChirho {
                    subject_chirho: subject_chirho.clone(),
                    owner_chirho:
                        crate::dag_private_value_chirho::PrivateValueOwnerChirho::RequestActorChirho,
                },
                crate::dag_private_value_chirho::PrivateDagValueContextChirho::default(),
                None,
                attribution_source_chirho,
            )?
        }
    };
    if stored_chirho != admission_chirho.request_chirho {
        bail!("run-intent request hash changed before admission");
    }
    Ok(())
}

fn persist_deferred_public_request_chirho(
    root_chirho: &Path,
    input_chirho: &dag_chirho::DagInputValueChirho,
    admission_chirho: &RunIntentAdmissionChirho,
) -> Result<()> {
    if admission_chirho
        .caller_idempotency_key_digest_chirho
        .is_none()
        || admission_chirho.request_private_subject_chirho.is_some()
    {
        return Ok(());
    }
    let dag_chirho::DagInputValueChirho::PublicBytesChirho(bytes_chirho) = input_chirho else {
        bail!("keyed public run-intent admission carries a private request value");
    };
    let stored_chirho = cas_chirho::add_chirho(root_chirho, bytes_chirho)?;
    if stored_chirho != admission_chirho.request_chirho {
        bail!("keyed public run-intent request hash changed before admission");
    }
    Ok(())
}

fn latest_verified_run_intent_record_for_admission_chirho(
    root_chirho: &Path,
    admission_chirho: &RunIntentAdmissionChirho,
) -> Result<Option<RunIntentRecordChirho>> {
    // Checkpoint brick S3, option (a) (agy #25851): the view folds only the records appended since the last call, each
    // verified once; the run being admitted, the only one whose effect can run, is re-verified fresh. The order is the
    // whole-log pass's: its record verifies before the caller-key check, so a double fault refuses the same way.
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        let lookup_chirho = admission_view_chirho::admission_lookup_chirho(
            root_chirho,
            &admission_chirho.run_chirho,
            admission_chirho
                .caller_idempotency_key_digest_chirho
                .as_ref(),
            &admission_chirho.idempotency_context_hash_chirho,
        )?;
        if let Some(latest_chirho) = &lookup_chirho.latest_chirho {
            admission_view_chirho::reverify_fresh_chirho(root_chirho, latest_chirho)?;
        }
        if lookup_chirho.caller_key_collides_chirho {
            bail!(
                "RelayCallerKeyCollisionChirho: caller idempotency key is already bound to different request evidence"
            );
        }
        Ok(lookup_chirho.latest_chirho)
    })
}

fn run_intent_execution_lock_name_chirho(admission_chirho: &RunIntentAdmissionChirho) -> String {
    match &admission_chirho.caller_idempotency_key_digest_chirho {
        Some(caller_key_digest_chirho) => format!(
            "run-intent-caller-key-v1-chirho:{}",
            caller_key_digest_chirho.0
        ),
        None => format!(
            "run-intent-execution-v1-chirho:{}",
            admission_chirho.run_chirho.0
        ),
    }
}

fn run_admitted_dag_chirho(
    root_chirho: &Path,
    dag_chirho: &DagChirho,
    input_chirho: dag_chirho::DagInputValueChirho,
    request_context_chirho: Option<&RequestContextChirho>,
    admission_chirho: &RunIntentAdmissionChirho,
    mode_chirho: RunIntentExecutionModeChirho,
    runtime_ports_chirho: super::DagEffectRuntimePortsChirho<'_>,
) -> Result<dag_chirho::DagRunReportChirho> {
    let input_for_run_chirho = input_chirho.clone();
    let run_chirho = || match input_for_run_chirho.clone() {
        dag_chirho::DagInputValueChirho::PublicBytesChirho(bytes_chirho) => {
            dag_chirho::run_dag_with_context_and_effect_runtime_chirho(
                root_chirho,
                dag_chirho,
                &bytes_chirho,
                request_context_chirho,
                runtime_ports_chirho,
            )
        }
        // S5a: the run reuses the request its admission stored, rather than storing it again.
        dag_chirho::DagInputValueChirho::PrivateBytesChirho {
            subject_chirho,
            bytes_chirho,
        } => dag_chirho::run_dag_with_admitted_private_input_and_effect_runtime_chirho(
            root_chirho,
            dag_chirho,
            &subject_chirho,
            &bytes_chirho,
            &admission_chirho.request_chirho,
            request_context_chirho,
            runtime_ports_chirho,
        ),
    };
    let result_chirho = with_run_intent_execution_mode_chirho(
        &admission_chirho.run_chirho,
        mode_chirho,
        run_chirho,
    );
    match result_chirho {
        Ok(report_chirho) => {
            if mode_chirho.records_terminal_chirho() {
                append_run_intent_record_chirho(
                    root_chirho,
                    admission_chirho,
                    RunIntentWriteStatusChirho::DoneChirho,
                    None,
                )
                .map_err(|error_chirho| {
                    wrap_dag_execution_stage_chirho(
                        DagExecutionRefusalIdentityChirho::RunIntentTerminalRecordRefusedChirho,
                        error_chirho,
                    )
                })
                .map_err(|error_chirho| {
                    wrap_dag_execution_attempt_chirho(
                        error_chirho,
                        mode_chirho.attempt_ordinal_chirho(),
                        None,
                    )
                })?;
            }
            Ok(report_chirho)
        }
        Err(error_chirho) => {
            let observation_chirho = dag_execution_refusal_observation_chirho(&error_chirho);
            if mode_chirho.records_terminal_chirho() {
                let internal_error_chirho = format!("{error_chirho:#}");
                let digest_chirho = cas_chirho::hash_chirho(internal_error_chirho.as_bytes());
                if let Err(record_error_chirho) = append_run_intent_record_chirho(
                    root_chirho,
                    admission_chirho,
                    RunIntentWriteStatusChirho::FailedChirho,
                    Some((
                        observation_chirho.identity_chirho().as_str_chirho(),
                        digest_chirho,
                    )),
                ) {
                    let record_error_chirho = wrap_dag_execution_stage_chirho(
                        DagExecutionRefusalIdentityChirho::RunIntentFailureRecordRefusedChirho,
                        record_error_chirho,
                    );
                    return Err(wrap_dag_execution_attempt_chirho(
                        record_error_chirho,
                        mode_chirho.attempt_ordinal_chirho(),
                        Some(observation_chirho.identity_chirho()),
                    ));
                }
            }
            Err(wrap_dag_execution_attempt_chirho(
                error_chirho,
                mode_chirho.attempt_ordinal_chirho(),
                None,
            ))
        }
    }
}

fn run_intent_admission_from_record_chirho(
    record_chirho: &RunIntentRecordChirho,
) -> RunIntentAdmissionChirho {
    RunIntentAdmissionChirho {
        run_chirho: record_chirho.run_chirho.clone(),
        dag_chirho: record_chirho.dag_chirho.clone(),
        request_chirho: record_chirho.request_chirho.clone(),
        request_private_subject_chirho: record_chirho.request_private_subject_chirho.clone(),
        caller_idempotency_key_digest_chirho: record_chirho
            .caller_idempotency_key_digest_chirho
            .clone(),
        caller_operation_digest_chirho: record_chirho.caller_operation_digest_chirho.clone(),
        idempotency_context_hash_chirho: record_chirho.idempotency_context_hash_chirho.clone(),
        scope_chirho: record_chirho.scope_chirho.clone(),
    }
}

pub fn run_intent_subject_index_hashes_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
) -> Result<RunIntentSubjectIndexHashesChirho> {
    Ok(RunIntentSubjectIndexHashesChirho {
        user_principal_hash_chirho: scope_value_hash_chirho(
            root_chirho,
            "user_principal_hash_chirho",
            subject_chirho,
        )?,
        owner_principal_hash_chirho: scope_value_hash_chirho(
            root_chirho,
            "owner_principal_hash_chirho",
            subject_chirho,
        )?,
    })
}

pub fn run_intent_subject_matches_chirho(
    record_chirho: &RunIntentRecordChirho,
    subject_hashes_chirho: &RunIntentSubjectIndexHashesChirho,
) -> Vec<String> {
    let mut matches_chirho = Vec::new();
    if record_chirho
        .scope_chirho
        .user_principal_hash_chirho
        .as_deref()
        == Some(subject_hashes_chirho.user_principal_hash_chirho.as_str())
    {
        matches_chirho.push("scope_chirho.user_principal_hash_chirho".to_string());
    }
    if record_chirho
        .scope_chirho
        .owner_principal_hash_chirho
        .as_deref()
        == Some(subject_hashes_chirho.owner_principal_hash_chirho.as_str())
    {
        matches_chirho.push("scope_chirho.owner_principal_hash_chirho".to_string());
    }
    matches_chirho
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RunIntentAdmissionChirho {
    run_chirho: HashChirho,
    dag_chirho: HashChirho,
    request_chirho: HashChirho,
    request_private_subject_chirho: Option<String>,
    caller_idempotency_key_digest_chirho: Option<HashChirho>,
    caller_operation_digest_chirho: Option<HashChirho>,
    idempotency_context_hash_chirho: HashChirho,
    scope_chirho: RunIntentScopeChirho,
}

/// The statuses this release WRITES. `aborted-chirho` is read but never written here (agy #25907): readers ship one
/// release before writers, so the writer brick adds its variant one release after this reader ships. The append door
/// takes this type and is the only production constructor of a record, so a write this release must not make cannot
/// be expressed at the door. The source-scan guard `ha1_run_intent_aborted_reader_guard_tests_chirho` pins the rest:
/// one production constructor, and one production spelling of `aborted-chirho`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunIntentWriteStatusChirho {
    PendingChirho,
    RunningChirho,
    DoneChirho,
    FailedChirho,
    /// Tests only: any status, such as one this release reads but never writes, to prove the readers.
    #[cfg(test)]
    CraftedChirho(&'static str),
}

impl RunIntentWriteStatusChirho {
    fn as_str_chirho(self) -> &'static str {
        match self {
            Self::PendingChirho => RUN_INTENT_PENDING_CHIRHO,
            Self::RunningChirho => RUN_INTENT_RUNNING_CHIRHO,
            Self::DoneChirho => RUN_INTENT_DONE_CHIRHO,
            Self::FailedChirho => RUN_INTENT_FAILED_CHIRHO,
            #[cfg(test)]
            Self::CraftedChirho(status_chirho) => status_chirho,
        }
    }
}

fn append_run_intent_record_chirho(
    root_chirho: &Path,
    admission_chirho: &RunIntentAdmissionChirho,
    status_chirho: RunIntentWriteStatusChirho,
    error_chirho: Option<(&str, HashChirho)>,
) -> Result<RunIntentRecordChirho> {
    let path_chirho = run_intent_records_path_chirho(root_chirho);
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        // Checkpoint brick S3, the S1 store rule: the view is brought current FIRST and refuses on a complete bad line
        // while it is still in the log; only then may recovery repair an unterminated tail, and the counts must agree.
        let verified_records_chirho =
            admission_view_chirho::current_run_intent_record_count_chirho(root_chirho)?;
        let seq_chirho = seqlog_chirho::recover_jsonl_len_unlocked_chirho(&path_chirho)?;
        if seq_chirho != verified_records_chirho {
            bail!(
                "run-intent log holds {seq_chirho} records by recovery but {verified_records_chirho} verified records; \
                 refusing to append"
            );
        }
        let mut record_chirho = RunIntentRecordChirho {
            schema_chirho: run_intent_record_schema_chirho(admission_chirho).to_string(),
            seq_chirho,
            run_chirho: admission_chirho.run_chirho.clone(),
            dag_chirho: admission_chirho.dag_chirho.clone(),
            request_chirho: admission_chirho.request_chirho.clone(),
            request_private_subject_chirho: admission_chirho.request_private_subject_chirho.clone(),
            caller_idempotency_key_digest_chirho: admission_chirho
                .caller_idempotency_key_digest_chirho
                .clone(),
            caller_operation_digest_chirho: admission_chirho.caller_operation_digest_chirho.clone(),
            idempotency_context_hash_chirho: admission_chirho
                .idempotency_context_hash_chirho
                .clone(),
            scope_chirho: admission_chirho.scope_chirho.clone(),
            status_chirho: status_chirho.as_str_chirho().to_string(),
            error_kind_chirho: error_chirho
                .as_ref()
                .map(|(kind_chirho, _)| (*kind_chirho).to_string()),
            error_digest_chirho: error_chirho.map(|(_, digest_chirho)| digest_chirho),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = run_intent_record_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
            &path_chirho,
            seq_chirho,
            &record_chirho,
        )?;
        Ok(record_chirho)
    })
}

fn run_intent_scope_chirho(
    root_chirho: &Path,
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<RunIntentScopeChirho> {
    let Some(context_chirho) = request_context_chirho else {
        return Ok(RunIntentScopeChirho {
            kind_chirho: "public-run-chirho".to_string(),
            app_hash_chirho: None,
            user_principal_hash_chirho: None,
            owner_principal_hash_chirho: None,
            client_id_hash_chirho: None,
            token_hash_chirho: None,
            price_book_chirho: None,
            billing_policy_chirho: None,
        });
    };
    Ok(RunIntentScopeChirho {
        kind_chirho: "app-run-chirho".to_string(),
        app_hash_chirho: Some(scope_value_hash_chirho(
            root_chirho,
            "app_hash_chirho",
            &context_chirho.app_chirho,
        )?),
        user_principal_hash_chirho: Some(scope_value_hash_chirho(
            root_chirho,
            "user_principal_hash_chirho",
            &context_chirho.user_principal_chirho,
        )?),
        owner_principal_hash_chirho: Some(scope_value_hash_chirho(
            root_chirho,
            "owner_principal_hash_chirho",
            &context_chirho.owner_principal_chirho,
        )?),
        client_id_hash_chirho: Some(scope_value_hash_chirho(
            root_chirho,
            "client_id_hash_chirho",
            &context_chirho.client_id_chirho,
        )?),
        token_hash_chirho: Some(context_chirho.token_hash_chirho.clone()),
        price_book_chirho: context_chirho.price_book_chirho.clone(),
        billing_policy_chirho: context_chirho.billing_policy_chirho.clone(),
    })
}

#[cfg(test)]
fn run_intent_context_hash_chirho(
    dag_chirho: &HashChirho,
    request_chirho: &HashChirho,
    scope_chirho: &RunIntentScopeChirho,
) -> Result<HashChirho> {
    run_intent_context_hash_from_digest_chirho(
        dag_chirho,
        request_chirho,
        scope_chirho,
        None,
        None,
        None,
    )
}

fn run_intent_context_hash_from_digest_chirho(
    dag_chirho: &HashChirho,
    request_chirho: &HashChirho,
    scope_chirho: &RunIntentScopeChirho,
    request_private_subject_chirho: Option<&str>,
    caller_idempotency_key_digest_chirho: Option<&HashChirho>,
    caller_operation_digest_chirho: Option<&HashChirho>,
) -> Result<HashChirho> {
    match caller_idempotency_key_digest_chirho {
        Some(caller_idempotency_key_digest_chirho) => {
            store_chirho::hash_object_chirho(&KeyedRunIntentIdempotencyContextChirho {
                schema_chirho: if caller_operation_digest_chirho.is_some() {
                    "run-intent-idempotency-context-v3-chirho".to_string()
                } else {
                    "run-intent-idempotency-context-v2-chirho".to_string()
                },
                dag_chirho: dag_chirho.clone(),
                request_chirho: request_chirho.clone(),
                request_private_subject_chirho: request_private_subject_chirho.map(str::to_string),
                caller_idempotency_key_digest_chirho: caller_idempotency_key_digest_chirho.clone(),
                caller_operation_digest_chirho: caller_operation_digest_chirho.cloned(),
                caller_scope_chirho: run_intent_caller_scope_chirho(scope_chirho),
            })
        }
        None => store_chirho::hash_object_chirho(&RunIntentIdempotencyContextChirho {
            schema_chirho: "run-intent-idempotency-context-v1-chirho".to_string(),
            dag_chirho: dag_chirho.clone(),
            request_chirho: request_chirho.clone(),
            caller_idempotency_key_digest_chirho: None,
            scope_chirho: scope_chirho.clone(),
        }),
    }
}

fn run_intent_caller_scope_chirho(
    scope_chirho: &RunIntentScopeChirho,
) -> RunIntentCallerScopeChirho {
    RunIntentCallerScopeChirho {
        kind_chirho: scope_chirho.kind_chirho.clone(),
        app_hash_chirho: scope_chirho.app_hash_chirho.clone(),
        user_principal_hash_chirho: scope_chirho.user_principal_hash_chirho.clone(),
    }
}

fn run_intent_admission_matches_chirho(
    durable_chirho: &RunIntentAdmissionChirho,
    current_chirho: &RunIntentAdmissionChirho,
) -> bool {
    if durable_chirho
        .caller_idempotency_key_digest_chirho
        .is_none()
    {
        return durable_chirho == current_chirho;
    }
    durable_chirho.run_chirho == current_chirho.run_chirho
        && durable_chirho.dag_chirho == current_chirho.dag_chirho
        && durable_chirho.request_chirho == current_chirho.request_chirho
        && durable_chirho.request_private_subject_chirho
            == current_chirho.request_private_subject_chirho
        && durable_chirho.caller_idempotency_key_digest_chirho
            == current_chirho.caller_idempotency_key_digest_chirho
        && durable_chirho.caller_operation_digest_chirho
            == current_chirho.caller_operation_digest_chirho
        && durable_chirho.idempotency_context_hash_chirho
            == current_chirho.idempotency_context_hash_chirho
        && run_intent_caller_scope_chirho(&durable_chirho.scope_chirho)
            == run_intent_caller_scope_chirho(&current_chirho.scope_chirho)
}

fn caller_idempotency_key_digest_chirho(
    caller_idempotency_key_chirho: &CallerIdempotencyKeyChirho,
) -> HashChirho {
    HashChirho(caller_idempotency_key_chirho.digest_hex_chirho())
}

fn caller_operation_digest_chirho(
    caller_operation_chirho: &CallerOperationBindingChirho,
) -> HashChirho {
    HashChirho(caller_operation_chirho.digest_hex_chirho())
}

fn run_intent_record_schema_chirho(admission_chirho: &RunIntentAdmissionChirho) -> &'static str {
    match (
        admission_chirho
            .caller_idempotency_key_digest_chirho
            .is_some(),
        admission_chirho.caller_operation_digest_chirho.is_some(),
    ) {
        (true, true) => RUN_INTENT_RECORD_SCHEMA_V3_CHIRHO,
        (true, false) => RUN_INTENT_RECORD_SCHEMA_V2_CHIRHO,
        (false, false) => RUN_INTENT_RECORD_SCHEMA_CHIRHO,
        (false, true) => unreachable!("caller operation binding requires a caller key"),
    }
}

fn run_intent_run_hash_chirho(idempotency_context_hash_chirho: &HashChirho) -> Result<HashChirho> {
    store_chirho::hash_object_chirho(&RunIntentRunIdentityChirho {
        schema_chirho: "run-intent-run-identity-v1-chirho".to_string(),
        idempotency_context_hash_chirho: idempotency_context_hash_chirho.clone(),
    })
}

fn scope_value_hash_chirho(
    root_chirho: &Path,
    label_chirho: &str,
    value_chirho: &str,
) -> Result<String> {
    let key_chirho = run_intent_scope_index_key_chirho(root_chirho)?;
    let mut hasher_chirho = blake3::Hasher::new_keyed(&key_chirho);
    hasher_chirho.update(label_chirho.as_bytes());
    hasher_chirho.update(&[0]);
    hasher_chirho.update(value_chirho.as_bytes());
    Ok(hasher_chirho.finalize().to_hex().to_string())
}

fn run_intent_scope_index_key_chirho(root_chirho: &Path) -> Result<[u8; 32]> {
    super::derive_instance_key_chirho(root_chirho, RUN_INTENT_SCOPE_INDEX_CONTEXT_CHIRHO)
}

fn run_intent_record_message_chirho(record_chirho: &RunIntentRecordChirho) -> Result<Vec<u8>> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

fn valid_status_chirho(status_chirho: &str) -> bool {
    matches!(
        status_chirho,
        RUN_INTENT_PENDING_CHIRHO
            | RUN_INTENT_RUNNING_CHIRHO
            | RUN_INTENT_DONE_CHIRHO
            | RUN_INTENT_FAILED_CHIRHO
            | RUN_INTENT_ABORTED_CHIRHO
    )
}

/// A run that startup recovery resumes. An aborted run is not one: it refused before any side effect and waits for its
/// own identical retry (agy #25907); the startup preflight's set agrees.
fn unfinished_status_chirho(status_chirho: &str) -> bool {
    matches!(
        status_chirho,
        RUN_INTENT_PENDING_CHIRHO | RUN_INTENT_RUNNING_CHIRHO
    )
}

fn now_ms_chirho() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
#[path = "run_intent_chirho/tests_chirho.rs"]
mod tests_chirho;

#[cfg(test)]
#[path = "run_intent_chirho/caller_key_tests_chirho.rs"]
mod caller_key_tests_chirho;

#[cfg(test)]
#[path = "run_intent_chirho/private_subject_verified_record_tests_chirho.rs"]
mod private_subject_verified_record_tests_chirho;

#[cfg(test)]
#[path = "run_intent_chirho/private_value_one_pass_tests_chirho.rs"]
mod private_value_one_pass_tests_chirho;

#[cfg(test)]
#[path = "run_intent_chirho/admission_view_tests_chirho.rs"]
mod admission_view_tests_chirho;

#[cfg(test)]
#[path = "run_intent_chirho/resume_attribution_tests_chirho.rs"]
mod resume_attribution_tests_chirho;
