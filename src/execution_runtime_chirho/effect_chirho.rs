// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The blessed effect layer — the small, signed set that touches the world.
//!
//! Pure nodes are a function of their inputs; *effects* (`ClockChirho`, `RandomChirho`,
//! reads, and reify = `WriteStoreChirho`) are the only capability-holders, and every effect
//! is recorded as a signed, idempotency-keyed `EffectChirho`. Because each non-volatile effect
//! records its result, most effects are non-deterministic on first run but **deterministic on
//! replay** (Temporal's trick). Live `ReadStoreChirho` effects deliberately re-execute and refresh
//! their effect slot instead of replaying so app views can observe the current store. Legacy
//! `QueryChirho` effect execution refuses until the CF4 projection-read composition replaces it.
//! Each live execution is also appended to
//! `volatile-effects-chirho.jsonl` so the latest slot stays compatible while the execution history
//! remains auditable.
//!
//! v1 scope (honest): effects are cairn-side built-in Rust; each effect is ed25519-**signed**
//! (one instance key; per-node keys deferred) and verified on load. Implemented:
//! `ClockChirho`, `RandomChirho`, `WriteStoreChirho` (reify), `ReadStoreChirho`,
//! `PaidEffectChirho`, `QueryChirho`, `NetChirho`, `InvokeChirho`, and
//! `TemplateAppDeployChirho`. Store capability keys are validated by `tenant_chirho`;
//! cross-tenant isolation comes from per-tenant roots.

use crate::model_chirho::{
    effect_signing_message_chirho, CapabilityChirho, EffectChirho, HashChirho, RequestContextChirho,
};
#[cfg(test)]
use crate::versioned_chirho;
use crate::{
    app_chirho, cache_chirho, cas_chirho, dag_private_value_chirho, durable_chirho,
    native_worker_chirho, seqlog_chirho, store_chirho,
};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_CHIRHO, Engine as _};
use cairn_signer_chirho::signer_chirho;
use serde::Serialize;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use url::Url;

#[path = "effect_chirho/llm_served_chirho.rs"]
pub mod llm_served_chirho;
#[path = "effect_chirho/net_private_chirho.rs"]
mod net_private_chirho;
#[path = "effect_chirho/postgres_reversible_chirho.rs"]
pub mod postgres_reversible_chirho;
#[path = "effect_chirho/projection_read_chirho.rs"]
pub mod projection_read_chirho;
#[path = "effect_chirho/run_intent_chirho.rs"]
pub mod run_intent_chirho;
#[path = "effect_chirho/run_options_chirho.rs"]
mod run_options_chirho;
#[path = "effect_chirho/runtime_ports_chirho.rs"]
pub mod runtime_ports_chirho;
#[path = "effect_chirho/store_effect_chirho.rs"]
mod store_effect_chirho;
pub(crate) use run_intent_chirho::{
    run_intent_cached_billing_suppressed_chirho, run_intent_volatile_replay_active_chirho,
};
pub(crate) use run_options_chirho::AdmittedEffectRunOptionsChirho;
use run_options_chirho::EffectRunOptionsChirho;
pub use run_options_chirho::EffectValueStorageChirho;
pub use runtime_ports_chirho::DagEffectRuntimePortsChirho;
pub(crate) use store_effect_chirho::store_seal_response_subject_chirho;
#[cfg(test)]
use store_effect_chirho::versioned_path_chirho;
#[path = "effect_chirho/types_chirho.rs"]
mod types_chirho;
#[path = "effect_chirho/viewer_state_chirho/mod_chirho.rs"]
mod viewer_state_chirho;
pub use net_private_chirho::net_response_body_bytes_chirho;
pub use net_private_chirho::PrivateNetPartsChirho;
pub use types_chirho::{
    InvokeResponseChirho, NetRequestChirho, NetResponseChirho, ScopedQueryRequestChirho,
    ScopedQueryResponseChirho, ScopedWriteStoreRequestChirho, ViewerStateActionChirho,
    ViewerStateConflictChirho, ViewerStateMutationReceiptChirho, ViewerStateRequestChirho,
    ViewerStateResponseChirho, ViewerStateVersionChirho, VolatileEffectDisplayRecordChirho,
    VolatileEffectRecordChirho,
};
pub(crate) use viewer_state_chirho::validate_viewer_state_logical_key_chirho;
pub(crate) use viewer_state_chirho::viewer_state_capability_prefix_chirho;
pub(crate) use viewer_state_chirho::with_verified_head_value_for_key_chirho;

/// Fail-closed bridge while CF6 removes the legacy money spine.
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf6-regenesis-boundary-chirho.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LegacyMoneyRoadChirho {
    PaidEffectChirho,
    QueryEffectChirho,
    CachedPaidEffectChirho,
    RealtimeSessionChirho,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LegacyMoneyRoadRefusedChirho {
    road_chirho: LegacyMoneyRoadChirho,
    effect_chirho: String,
}

impl LegacyMoneyRoadRefusedChirho {
    pub(crate) fn new_chirho(
        road_chirho: LegacyMoneyRoadChirho,
        effect_chirho: impl Into<String>,
    ) -> Self {
        Self {
            road_chirho,
            effect_chirho: effect_chirho.into(),
        }
    }
}

impl std::fmt::Display for LegacyMoneyRoadRefusedChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter_chirho,
            "legacy money road {:?} for '{}' is unavailable; compose a reviewed ledger-substrate authority",
            self.road_chirho, self.effect_chirho
        )
    }
}

impl std::error::Error for LegacyMoneyRoadRefusedChirho {}

/// Refuse the pre-regenesis realtime money protocol through the same typed law as every other
/// legacy money road. The public helper exposes no constructor or caller-selected coordinate.
pub fn refuse_legacy_realtime_money_road_chirho() -> Result<()> {
    Err(anyhow::Error::new(
        LegacyMoneyRoadRefusedChirho::new_chirho(
            LegacyMoneyRoadChirho::RealtimeSessionChirho,
            "realtime_chirho",
        ),
    ))
}

thread_local! {
    static INVOKE_DEPTH_CHIRHO: Cell<u32> = const { Cell::new(0) };
    static INVOKE_FUEL_REMAINING_CHIRHO: Cell<u64> = const { Cell::new(MAX_INVOKE_TOTAL_FUEL_CHIRHO) };
}

const MAX_INVOKE_DEPTH_CHIRHO: u32 = 16;
const MAX_INVOKE_TOTAL_FUEL_CHIRHO: u64 = 50_000_000;
const MAX_NET_REQUEST_BYTES_CHIRHO: usize = 64 * 1024;
const DEFAULT_NET_RESPONSE_BYTES_CHIRHO: usize = 256 * 1024;
const MAX_NET_RESPONSE_BYTES_CHIRHO: usize = 1024 * 1024;
const DEFAULT_NET_TIMEOUT_MS_CHIRHO: u64 = 5_000;
const MAX_NET_TIMEOUT_MS_CHIRHO: u64 = 30_000;
const SAFE_NET_HEADERS_CHIRHO: &[&str] = &["accept", "content-type", "user-agent"];
pub const SCOPED_WRITE_STORE_SCHEMA_CHIRHO: &str = "scoped-write-store-v1-chirho";
pub const VOLATILE_EFFECT_RECORD_SCHEMA_CHIRHO: &str = "volatile-effect-record-v1-chirho";

struct ValidatedNetRequestChirho {
    request_chirho: NetRequestChirho,
    method_chirho: String,
    url_chirho: Url,
    body_chirho: Vec<u8>,
    timeout_ms_chirho: u64,
    max_response_bytes_chirho: usize,
}

struct InvokeGuardChirho;

impl Drop for InvokeGuardChirho {
    fn drop(&mut self) {
        INVOKE_DEPTH_CHIRHO.with(|depth_chirho| {
            depth_chirho.set(depth_chirho.get().saturating_sub(1));
        });
    }
}

/// A "volatile" effect observes mutable state and must re-execute every run — never replayed
/// from the log or served from the run-cache. Store reads and query reads are live views;
/// `Clock`/`Random` use record-replay (a value captured once per logical run), so they are NOT
/// volatile here.
pub fn is_volatile_chirho(capability_chirho: &CapabilityChirho) -> bool {
    matches!(
        capability_chirho,
        CapabilityChirho::ReadStoreChirho { .. } | CapabilityChirho::QueryChirho { .. }
    )
}

/// Validate an effect request before a DAG source input is written to CAS. This keeps obviously
/// unsafe NetChirho requests (notably secret-bearing headers) out of the immutable input store.
pub fn preflight_effect_request_chirho(
    capabilities_chirho: &[CapabilityChirho],
    request_bytes_chirho: &[u8],
) -> Result<()> {
    for capability_chirho in capabilities_chirho {
        if let CapabilityChirho::NetChirho { allowlist_chirho } = capability_chirho {
            let _ = validate_net_request_chirho(allowlist_chirho, request_bytes_chirho)?;
        }
    }
    Ok(())
}

fn effect_path_chirho(root_chirho: &Path, idem_chirho: &HashChirho) -> PathBuf {
    root_chirho.join("effects-chirho").join(&idem_chirho.0)
}

pub fn volatile_effect_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("volatile-effects-chirho.jsonl")
}

/// Load a previously-logged effect by its idempotency key (the replay path).
pub fn load_effect_chirho(
    root_chirho: &Path,
    idem_chirho: &HashChirho,
) -> Result<Option<EffectChirho>> {
    let path_chirho = effect_path_chirho(root_chirho, idem_chirho);
    if !path_chirho.exists() {
        return Ok(None);
    }
    let bytes_chirho =
        std::fs::read(&path_chirho).with_context(|| format!("read {}", path_chirho.display()))?;
    let effect_chirho: EffectChirho =
        serde_json::from_slice(&bytes_chirho).context("decode EffectChirho")?;
    // Tamper-evidence: a logged effect must verify against the instance key on load.
    verify_effect_chirho(root_chirho, &effect_chirho)?;
    Ok(Some(effect_chirho))
}

fn store_effect_chirho(root_chirho: &Path, effect_chirho: &EffectChirho) -> Result<()> {
    let path_chirho = effect_path_chirho(root_chirho, &effect_chirho.idem_key_chirho);
    if let Some(parent_chirho) = path_chirho.parent() {
        std::fs::create_dir_all(parent_chirho)?;
    }
    let bytes_chirho = serde_json::to_vec_pretty(effect_chirho).context("encode EffectChirho")?;
    durable_chirho::write_file_durable_chirho(&path_chirho, &bytes_chirho)
        .context("write EffectChirho")?;
    Ok(())
}

pub fn load_volatile_effect_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<VolatileEffectRecordChirho>> {
    let path_chirho = volatile_effect_records_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut records_chirho = Vec::new();
    for (idx_chirho, line_chirho) in text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .enumerate()
    {
        let record_chirho: VolatileEffectRecordChirho =
            serde_json::from_str(line_chirho).context("decode VolatileEffectRecordChirho")?;
        if record_chirho.seq_chirho != idx_chirho as u64 {
            bail!(
                "volatile effect record seq {} did not match line {}",
                record_chirho.seq_chirho,
                idx_chirho
            );
        }
        verify_volatile_effect_record_chirho(root_chirho, &record_chirho)?;
        records_chirho.push(record_chirho);
    }
    Ok(records_chirho)
}

fn replay_volatile_effect_for_resume_chirho(
    root_chirho: &Path,
    idem_key_chirho: &HashChirho,
    capability_chirho: &CapabilityChirho,
    request_bytes_chirho: &[u8],
) -> Result<Option<EffectChirho>> {
    if !run_intent_volatile_replay_active_chirho() {
        return Ok(None);
    }
    let request_hash_chirho = cas_chirho::hash_chirho(request_bytes_chirho);
    let Some(effect_chirho) = load_volatile_effect_records_chirho(root_chirho)?
        .into_iter()
        .rev()
        .map(|record_chirho| record_chirho.effect_chirho)
        .find(|effect_chirho| {
            effect_chirho.idem_key_chirho == *idem_key_chirho
                && effect_chirho.capability_chirho == *capability_chirho
                && effect_chirho.request_chirho == request_hash_chirho
        })
    else {
        return Ok(None);
    };
    let response_chirho = effect_chirho
        .response_chirho
        .as_ref()
        .ok_or_else(|| anyhow!("volatile resume effect has no response"))?;
    // The resumed response is EVIDENCE, not data — this proves it is still resolvable before the
    // prior effect is replayed. Since F4 sealing (S3) a live-read response rests as a private DAG
    // value rather than a public CAS object, so a bare `cas_chirho::get_chirho` here would refuse
    // every sealed read on resume. Resolution must still be fail-closed: a private hash counts only
    // when a record that VERIFIES claims it.
    // And ABSENCE is what earns the private route — not "the public read failed". A tampered public
    // object is PRESENT; letting it take the private branch would replay an effect over an object
    // that is being actively corrupted, on the evidence of a record that never mentioned it.
    match cas_chirho::read_verified_chirho(root_chirho, response_chirho) {
        cas_chirho::CasReadOutcomeChirho::VerifiedChirho(_bytes_chirho) => {}
        cas_chirho::CasReadOutcomeChirho::AbsentChirho(_absent_chirho) => {
            if dag_private_value_chirho::verified_private_dag_value_record_chirho(
                root_chirho,
                response_chirho,
            )
            .with_context(|| format!("volatile resume response {} missing", response_chirho.0))?
            .is_none()
            {
                bail!("volatile resume response {} missing", response_chirho.0);
            }
        }
        cas_chirho::CasReadOutcomeChirho::TamperedChirho { actual_chirho, .. } => bail!(
            "volatile resume response {} is present in public CAS and re-hashes to {}",
            response_chirho.0,
            actual_chirho.0
        ),
        cas_chirho::CasReadOutcomeChirho::UnreadableChirho(error_chirho) => bail!(
            "volatile resume response {} is present but could not be read: {error_chirho}",
            response_chirho.0
        ),
    }
    Ok(Some(effect_chirho))
}

/// Whether one logged value hash still resolves — as a public CAS object that re-hashes, or as a
/// private DAG value whose record verifies. Returns the label a listing shows when it does not.
///
/// Only ABSENCE from the public plane may be answered by the private one. A public object that is
/// present and does not re-hash is tamper, and a private record claiming the same hash must not
/// turn that into a row an operator reads as VALID — which is exactly what "any read failure may
/// fall back" did, on the surface whose whole job is to show an operator what is wrong.
fn display_value_resolution_error_chirho(
    root_chirho: &Path,
    verified_private_hashes_chirho: &std::collections::BTreeSet<HashChirho>,
    label_chirho: &str,
    hash_chirho: &HashChirho,
) -> Option<String> {
    match cas_chirho::read_verified_chirho(root_chirho, hash_chirho) {
        cas_chirho::CasReadOutcomeChirho::VerifiedChirho(_bytes_chirho) => None,
        cas_chirho::CasReadOutcomeChirho::AbsentChirho(_absent_chirho) => {
            if verified_private_hashes_chirho.contains(hash_chirho) {
                None
            } else {
                Some(format!(
                    "volatile effect {label_chirho} {} resolves neither as a public object nor as a verified private DAG value",
                    hash_chirho.0
                ))
            }
        }
        cas_chirho::CasReadOutcomeChirho::TamperedChirho { actual_chirho, .. } => Some(format!(
            "volatile effect {label_chirho} {} is present in public CAS and re-hashes to {}",
            hash_chirho.0, actual_chirho.0
        )),
        cas_chirho::CasReadOutcomeChirho::UnreadableChirho(error_chirho) => Some(format!(
            "volatile effect {label_chirho} {} is present in public CAS and could not be read: {error_chirho}",
            hash_chirho.0
        )),
    }
}

pub fn load_volatile_effect_records_for_display_chirho(
    root_chirho: &Path,
) -> Result<Vec<VolatileEffectDisplayRecordChirho>> {
    let path_chirho = volatile_effect_records_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    // Since F4 sealing a live read's response rests as a private DAG value, so a row whose response
    // no longer resolves is precisely the row an operator needs to SEE — labelled, not hidden, and
    // not suppressing the rest of the listing (M144). Resolved once for the whole listing so a
    // growing log cannot make this O(rows x private values).
    let verified_private_hashes_chirho =
        dag_private_value_chirho::verified_private_dag_value_hashes_chirho(root_chirho)?;
    let mut records_chirho = Vec::new();
    let mut expected_seq_chirho = 0_u64;
    for (line_idx_chirho, line_chirho) in text_chirho.lines().enumerate() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let line_number_chirho = line_idx_chirho as u64 + 1;
        let parsed_chirho = serde_json::from_str::<VolatileEffectRecordChirho>(line_chirho)
            .map_err(|error_chirho| format!("decode VolatileEffectRecordChirho: {error_chirho}"));
        match parsed_chirho {
            Ok(record_chirho) => {
                let validation_error_chirho = if record_chirho.seq_chirho != expected_seq_chirho {
                    Some(format!(
                        "volatile effect record seq {} did not match line {}",
                        record_chirho.seq_chirho, expected_seq_chirho
                    ))
                } else {
                    verify_volatile_effect_record_chirho(root_chirho, &record_chirho)
                        .err()
                        .map(|error_chirho| error_chirho.to_string())
                        .or_else(|| {
                            display_value_resolution_error_chirho(
                                root_chirho,
                                &verified_private_hashes_chirho,
                                "request",
                                &record_chirho.effect_chirho.request_chirho,
                            )
                        })
                        .or_else(|| {
                            record_chirho
                                .effect_chirho
                                .response_chirho
                                .as_ref()
                                .and_then(|response_chirho| {
                                    display_value_resolution_error_chirho(
                                        root_chirho,
                                        &verified_private_hashes_chirho,
                                        "response",
                                        response_chirho,
                                    )
                                })
                        })
                };
                records_chirho.push(VolatileEffectDisplayRecordChirho {
                    line_chirho: line_number_chirho,
                    record_chirho: Some(record_chirho),
                    validation_error_chirho,
                });
            }
            Err(error_chirho) => records_chirho.push(VolatileEffectDisplayRecordChirho {
                line_chirho: line_number_chirho,
                record_chirho: None,
                validation_error_chirho: Some(error_chirho),
            }),
        }
        expected_seq_chirho += 1;
    }
    Ok(records_chirho)
}

fn append_volatile_effect_record_chirho(
    root_chirho: &Path,
    effect_chirho: &EffectChirho,
) -> Result<VolatileEffectRecordChirho> {
    let path_chirho = volatile_effect_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        let mut record_chirho = VolatileEffectRecordChirho {
            schema_chirho: VOLATILE_EFFECT_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho,
            effect_chirho: effect_chirho.clone(),
            sig_chirho: String::new(),
        };
        let message_chirho = volatile_effect_record_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

/// Run one blessed effect, returning its logged `EffectChirho`. **Record-replay:** if an
/// effect with this idempotency key was already logged, it is returned unchanged (no
/// re-execution). The result *bytes* live in the CAS at `effect.response_chirho`.
pub fn run_effect_chirho(
    root_chirho: &Path,
    seq_chirho: u64,
    idem_key_chirho: HashChirho,
    capability_chirho: CapabilityChirho,
    request_bytes_chirho: &[u8],
) -> Result<EffectChirho> {
    run_effect_with_context_chirho(
        root_chirho,
        seq_chirho,
        idem_key_chirho,
        capability_chirho,
        request_bytes_chirho,
        None,
    )
}

pub fn run_effect_with_context_chirho(
    root_chirho: &Path,
    seq_chirho: u64,
    idem_key_chirho: HashChirho,
    capability_chirho: CapabilityChirho,
    request_bytes_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<EffectChirho> {
    run_effect_with_context_and_value_storage_chirho(
        root_chirho,
        seq_chirho,
        idem_key_chirho,
        capability_chirho,
        request_bytes_chirho,
        EffectValueStorageChirho::default(),
        request_context_chirho,
    )
}

pub fn run_effect_with_context_and_value_storage_chirho(
    root_chirho: &Path,
    seq_chirho: u64,
    idem_key_chirho: HashChirho,
    capability_chirho: CapabilityChirho,
    request_bytes_chirho: &[u8],
    storage_chirho: EffectValueStorageChirho,
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<EffectChirho> {
    let admission_chirho =
        crate::blessed_chirho::admit_legacy_operator_effect_chirho(&capability_chirho)?;
    // This entry admits a legacy OPERATOR effect, so a run here with no request context is the
    // operator's own: that is the proven reason its private values join no account.
    let operator_chirho =
        crate::privacy_chirho::PrivateBlobAttributionChirho::not_account_scoped_chirho(
            crate::privacy_chirho::NotAccountScopedReasonChirho::OperatorRunChirho,
        );
    run_effect_with_context_and_value_storage_authorized_chirho(
        root_chirho,
        seq_chirho,
        idem_key_chirho,
        capability_chirho,
        request_bytes_chirho,
        EffectRunOptionsChirho {
            storage_chirho,
            request_context_chirho,
            attribution_source_chirho:
                dag_private_value_chirho::RunAttributionSourceChirho::new_chirho(
                    request_context_chirho,
                    Some(&operator_chirho),
                ),
            admission_chirho: &admission_chirho,
            postgres_reversible_chirho: None,
            llm_served_chirho: None,
        },
    )
}

pub(crate) fn run_admitted_effect_with_context_and_value_storage_chirho(
    root_chirho: &Path,
    seq_chirho: u64,
    idem_key_chirho: HashChirho,
    capability_chirho: CapabilityChirho,
    request_bytes_chirho: &[u8],
    options_chirho: AdmittedEffectRunOptionsChirho<'_, '_, '_>,
) -> Result<EffectChirho> {
    let AdmittedEffectRunOptionsChirho {
        storage_chirho,
        request_context_chirho,
        attribution_source_chirho,
        admission_chirho,
        postgres_reversible_chirho,
        llm_served_chirho,
    } = options_chirho;
    run_effect_with_context_and_value_storage_authorized_chirho(
        root_chirho,
        seq_chirho,
        idem_key_chirho,
        capability_chirho,
        request_bytes_chirho,
        EffectRunOptionsChirho {
            storage_chirho,
            request_context_chirho,
            attribution_source_chirho,
            admission_chirho,
            postgres_reversible_chirho,
            llm_served_chirho,
        },
    )
}

fn run_effect_with_context_and_value_storage_authorized_chirho(
    root_chirho: &Path,
    seq_chirho: u64,
    idem_key_chirho: HashChirho,
    capability_chirho: CapabilityChirho,
    request_bytes_chirho: &[u8],
    options_chirho: EffectRunOptionsChirho<'_, '_, '_>,
) -> Result<EffectChirho> {
    let EffectRunOptionsChirho {
        storage_chirho,
        request_context_chirho,
        attribution_source_chirho,
        admission_chirho,
        postgres_reversible_chirho,
        llm_served_chirho,
    } = options_chirho;

    admission_chirho.authorize_chirho(&capability_chirho)?;
    admission_chirho.authorize_request_chirho(request_bytes_chirho)?;
    let viewer_state_request_chirho = match &capability_chirho {
        CapabilityChirho::ReadStoreChirho { .. } | CapabilityChirho::WriteStoreChirho { .. } => {
            store_effect_chirho::decode_viewer_state_request_chirho(request_bytes_chirho)?
        }
        _ => None,
    };
    let may_reuse_generic_effect_result_chirho =
        admission_chirho.may_reuse_generic_effect_result_chirho()?;
    if viewer_state_request_chirho.is_some()
        && storage_chirho.response_storage_chirho.is_some()
        && storage_chirho.request_hash_chirho.is_none()
    {
        bail!("viewer-state effect requests must arrive through the private DAG-value plane");
    }

    // Volatile effects (live reads) always re-execute; the rest replay by idempotency key.
    let volatile_chirho = is_volatile_chirho(&capability_chirho);
    if volatile_chirho {
        if let Some(prior_chirho) = replay_volatile_effect_for_resume_chirho(
            root_chirho,
            &idem_key_chirho,
            &capability_chirho,
            request_bytes_chirho,
        )? {
            return Ok(prior_chirho);
        }
    } else if may_reuse_generic_effect_result_chirho {
        if let Some(prior_chirho) = load_effect_chirho(root_chirho, &idem_key_chirho)? {
            if viewer_state_request_chirho.is_some()
                && (prior_chirho.capability_chirho != capability_chirho
                    || prior_chirho.request_chirho != cas_chirho::hash_chirho(request_bytes_chirho))
            {
                bail!("viewer-state idempotency key was reused for a different request");
            }
            return Ok(prior_chirho);
        }
    }

    // The blessed-effect gate: effects resolve ONLY through the signed blessed registry.
    if !crate::blessed_chirho::is_blessed_chirho(&capability_chirho) {
        return Err(anyhow!(
            "refusing unblessed effect '{}' — effects resolve only through the signed blessed registry",
            crate::blessed_chirho::capability_kind_chirho(&capability_chirho)
        ));
    }

    // Set by either store arm to the seal subject of the row it sealed (write) or unsealed (live
    // read). Its presence is what forces the effect's at-rest response copy private below
    // (F4 sealing §2.2 for the write door, §2.3 for the read door). One variable, so both doors
    // reach the single forcing site rather than growing a second privacy policy path.
    let mut sealed_value_subject_chirho: Option<(
        String,
        dag_private_value_chirho::PrivateValueOwnerChirho,
    )> = None;
    let response_bytes_chirho: Vec<u8> = match &capability_chirho {
        CapabilityChirho::ClockChirho => now_ms_chirho().to_le_bytes().to_vec(),
        CapabilityChirho::RandomChirho => random_u64_chirho().to_le_bytes().to_vec(),
        // Legacy reify writes raw input bytes to the capability key. A schema-tagged
        // ScopedWriteStoreRequestChirho can instead write a value under a caller-specified key
        // inside the capability prefix. Either way, the effect returns the value it wrote.
        //
        // F4 at-rest sealing: the value rests ONLY as a `SealedStoreValueChirho` envelope, while
        // the effect still returns the written plaintext IN MEMORY, so every guest DAG downstream
        // of a write receives byte-identical bytes and the response hash stays blake3(plaintext).
        CapabilityChirho::WriteStoreChirho { prefix_chirho } => {
            let output_chirho = store_effect_chirho::run_write_store_chirho(
                root_chirho,
                prefix_chirho,
                request_bytes_chirho,
                &idem_key_chirho,
                request_context_chirho,
                &attribution_source_chirho,
            )?;
            sealed_value_subject_chirho = output_chirho.private_domain_chirho;
            output_chirho.response_chirho
        }
        // live read: the key is the capability's `prefix_chirho`; returns the current value
        // (empty if absent). The input is ignored.
        //
        // F4 at-rest sealing §2.3: what rests is an envelope, so the arm unseals VIEWER-SCOPED and
        // hands the DAG the plaintext in memory only. The viewer scope is the admitted run itself;
        // per the private-data rule the response is therefore private by default, which is what
        // setting the seal subject below achieves — the live-read response object rests as a
        // private DAG value instead of in public CAS.
        CapabilityChirho::ReadStoreChirho { prefix_chirho } => {
            let output_chirho = store_effect_chirho::run_read_store_chirho(
                root_chirho,
                prefix_chirho,
                request_bytes_chirho,
                request_context_chirho,
            )?;
            sealed_value_subject_chirho = output_chirho.private_domain_chirho;
            output_chirho.response_chirho
        }
        CapabilityChirho::PaidEffectChirho {
            effect_chirho,
            ..
        } if effect_chirho
            == cairn_undo_plan_chirho::contract_chirho::POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO =>
        {
            postgres_reversible_chirho::run_postgres_reversible_chirho(
                root_chirho,
                admission_chirho,
                request_context_chirho,
                request_bytes_chirho,
                postgres_reversible_chirho,
            )
            .map_err(|error_chirho| {
                crate::dag_chirho::refusal_chirho::wrap_dag_execution_stage_chirho(
                    crate::dag_chirho::refusal_chirho::DagExecutionRefusalIdentityChirho::DagEffectProviderRefusedChirho,
                    error_chirho,
                )
            })?
        }
        CapabilityChirho::PaidEffectChirho {
            effect_chirho,
            ..
        } if effect_chirho
            == cairn_undo_plan_chirho::contract_chirho::LLM_SERVED_EFFECT_SUBTYPE_CHIRHO =>
        {
            let outcome_chirho = llm_served_chirho::run_llm_served_chirho(
                root_chirho,
                admission_chirho,
                request_context_chirho,
                request_bytes_chirho,
                llm_served_chirho,
            )
            .map_err(|error_chirho| {
                // A pre-dispatch refusal (composition unavailable, malformed request, money policy)
                // definitely did not run the provider; only an in-doubt terminal may have. The
                // knowledge marker distinguishes them for the product (PFE gpt #22471 note 2).
                let identity_chirho = if error_chirho
                    .downcast_ref::<llm_served_chirho::LlmServedActivationErrorChirho>()
                    .map(|activation_chirho| {
                        matches!(
                            activation_chirho,
                            llm_served_chirho::LlmServedActivationErrorChirho::InDoubtChirho { .. }
                        )
                    })
                    .unwrap_or(false)
                {
                    crate::dag_chirho::refusal_chirho::DagExecutionRefusalIdentityChirho::DagEffectProviderRefusedChirho
                } else {
                    crate::dag_chirho::refusal_chirho::DagExecutionRefusalIdentityChirho::DagPreEffectRefusedChirho
                };
                crate::dag_chirho::refusal_chirho::wrap_dag_execution_stage_chirho(
                    identity_chirho,
                    error_chirho,
                )
            })?;
            // The completion (if any) rests sealed to its viewer, the actor's own data; a refusal
            // body sets no subject.
            sealed_value_subject_chirho = outcome_chirho.private_subject_chirho.map(|subject_chirho| {
                (
                    subject_chirho,
                    dag_private_value_chirho::PrivateValueOwnerChirho::RequestActorChirho,
                )
            });
            outcome_chirho.response_chirho
        }
        CapabilityChirho::PaidEffectChirho { effect_chirho, .. } => {
            return Err(anyhow::Error::new(
                LegacyMoneyRoadRefusedChirho::new_chirho(
                    LegacyMoneyRoadChirho::PaidEffectChirho,
                    effect_chirho,
                ),
            ));
        }
        CapabilityChirho::QueryChirho {
            prefix_chirho,
            max_rows_chirho,
            ..
        } => run_query_effect_chirho(
            root_chirho,
            prefix_chirho,
            *max_rows_chirho,
            &idem_key_chirho,
            request_bytes_chirho,
            request_context_chirho,
        )?,
        CapabilityChirho::UserIdentityChirho { .. } => {
            bail!("UserIdentityChirho is an authorization capability, not an executable effect")
        }
        CapabilityChirho::AppContextChirho { .. } => {
            bail!("AppContextChirho is attribution context, not an executable effect")
        }
        CapabilityChirho::SecretRefChirho { .. } => {
            bail!("SecretRefChirho is resolved by host integration effects, not executed directly")
        }
        CapabilityChirho::RealtimeSessionChirho { .. } => {
            bail!("RealtimeSessionChirho is opened by realtime_chirho, not the short-run effect executor")
        }
        CapabilityChirho::SupportIssueChirho { .. } => {
            bail!("SupportIssueChirho is enforced by support_chirho, not the short-run effect executor")
        }
        CapabilityChirho::CausalReversionChirho { .. } => {
            bail!("CausalReversionChirho is an authorization capability, not an executable effect")
        }
        CapabilityChirho::NetChirho { allowlist_chirho } => {
            run_net_effect_chirho(root_chirho, allowlist_chirho, request_bytes_chirho)?
        }
        CapabilityChirho::InvokeChirho { node_chirho } => run_invoke_effect_chirho(
            root_chirho,
            node_chirho,
            request_bytes_chirho,
            request_context_chirho,
            attribution_source_chirho,
        )?,
        CapabilityChirho::TemplateAppDeployChirho { template_id_chirho } => {
            app_chirho::run_template_app_deploy_effect_chirho(
                root_chirho,
                template_id_chirho,
                request_bytes_chirho,
                request_context_chirho,
            )?
        }
    };

    // A sealed store effect's response IS the row's plaintext — the bytes a write just sealed, or
    // the bytes a live read just unsealed — so its at-rest copy must never land in public CAS; that
    // would rest the very bytes the seal removed from the store. A caller that already declared a
    // private subject keeps it (the invariant is "not public", not "this subject"), so downstream
    // edge-privacy resolution is unchanged; only a public-CAS response is forced private, under the
    // row's own seal subject.
    let mut storage_chirho = storage_chirho;
    if viewer_state_request_chirho.is_some() && storage_chirho.request_hash_chirho.is_none() {
        let (request_subject_chirho, request_owner_chirho) =
            sealed_value_subject_chirho
                .as_ref()
                .ok_or_else(|| anyhow!("viewer-state effect did not derive a private subject"))?;
        storage_chirho.request_hash_chirho = Some(
            dag_private_value_chirho::store_dag_value_with_policy_chirho(
                root_chirho,
                request_bytes_chirho,
                &dag_private_value_chirho::ValueStoragePolicyChirho::PrivateBlobRefChirho {
                    subject_chirho: request_subject_chirho.clone(),
                    owner_chirho: *request_owner_chirho,
                },
                dag_private_value_chirho::PrivateDagValueContextChirho::default(),
                None,
                &attribution_source_chirho,
            )?,
        );
    } else if matches!(
        &capability_chirho,
        CapabilityChirho::PaidEffectChirho { effect_chirho, .. }
            if effect_chirho
                == cairn_undo_plan_chirho::contract_chirho::LLM_SERVED_EFFECT_SUBTYPE_CHIRHO
    ) && storage_chirho.request_hash_chirho.is_none()
    {
        // Ruling 4 (S3): the served LLM effect does NOT arrive through the viewer-state private-DAG
        // plane, yet its REQUEST (the prompt) ALWAYS carries her free text (business name, phone,
        // email) whether the effect completes OR refuses. A refusal sets no response seal subject, so
        // anchoring the request copy to the response subject (`sealed_value_subject_chirho`) left the
        // refusal path resting the prompt in public CAS -- the S3-audit ruling-4 leak. Anchor it to
        // the ALWAYS-present viewer (`request_context_chirho.user_principal_chirho`) and seal the
        // request copy UNCONDITIONALLY for the LLM subtype, so `signed_effect_from_response_chirho`
        // never lands the prompt in public CAS on either outcome. On a completion this is the SAME
        // subject the response is sealed to (the viewer). Gated to the LLM subtype ALONE: the
        // viewer-state arm above is byte-unchanged, and the legacy reify write/read (WriteStore/
        // ReadStore with raw bytes) keep their accepted section 2.6 residual.
        let request_subject_chirho = request_context_chirho
            .map(|context_chirho| context_chirho.user_principal_chirho.clone())
            .ok_or_else(|| {
                anyhow!(
                    "served LLM effect has no request context to derive its viewer seal subject"
                )
            })?;
        storage_chirho.request_hash_chirho = Some(
            dag_private_value_chirho::store_dag_value_with_policy_chirho(
                root_chirho,
                request_bytes_chirho,
                &dag_private_value_chirho::ValueStoragePolicyChirho::PrivateBlobRefChirho {
                    subject_chirho: request_subject_chirho,
                    owner_chirho:
                        dag_private_value_chirho::PrivateValueOwnerChirho::RequestActorChirho,
                },
                dag_private_value_chirho::PrivateDagValueContextChirho::default(),
                None,
                &attribution_source_chirho,
            )?,
        );
    }
    let storage_chirho = match (
        sealed_value_subject_chirho,
        storage_chirho
            .response_storage_chirho
            .as_ref()
            .and_then(dag_private_value_chirho::ValueStoragePolicyChirho::private_subject_chirho),
    ) {
        (Some((seal_subject_chirho, seal_owner_chirho)), None) => EffectValueStorageChirho {
            response_storage_chirho: Some(
                dag_private_value_chirho::ValueStoragePolicyChirho::PrivateBlobRefChirho {
                    subject_chirho: seal_subject_chirho,
                    owner_chirho: seal_owner_chirho,
                },
            ),
            ..storage_chirho
        },
        _ => storage_chirho,
    };
    let effect_chirho = signed_effect_from_response_chirho(
        root_chirho,
        seq_chirho,
        idem_key_chirho,
        capability_chirho,
        request_bytes_chirho,
        &response_bytes_chirho,
        run_options_chirho::EffectResponseStorageChirho {
            storage_chirho,
            attribution_source_chirho,
        },
    )
    .map_err(|error_chirho| {
        crate::dag_chirho::refusal_chirho::wrap_dag_execution_stage_chirho(
            crate::dag_chirho::refusal_chirho::DagExecutionRefusalIdentityChirho::DagEffectTerminalAuditRefusedChirho,
            error_chirho,
        )
    })?;
    if volatile_chirho {
        append_volatile_effect_record_chirho(root_chirho, &effect_chirho).map_err(
            |error_chirho| {
                crate::dag_chirho::refusal_chirho::wrap_dag_execution_stage_chirho(
                    crate::dag_chirho::refusal_chirho::DagExecutionRefusalIdentityChirho::DagEffectResultAccountingRefusedChirho,
                    error_chirho,
                )
            },
        )?;
    }
    Ok(effect_chirho)
}

/// Run a `NetChirho` request with host-private headers. The request bytes are the only request
/// material written to CAS/effect logs; private headers are for trusted host integrations such as
/// `llm_chirho` secret injection and must never contain app-authored data. This helper treats
/// non-2xx responses as failed executions so transient provider errors do not poison the cache.
pub fn run_net_request_with_private_headers_chirho(
    root_chirho: &Path,
    seq_chirho: u64,
    idem_key_chirho: HashChirho,
    allowlist_chirho: &[String],
    request_bytes_chirho: &[u8],
    private_chirho: PrivateNetPartsChirho<'_>,
) -> Result<(EffectChirho, bool)> {
    let PrivateNetPartsChirho {
        headers_chirho: private_headers_chirho,
        body_subject_chirho: private_body_subject_chirho,
        attribution_chirho,
    } = private_chirho;
    let capability_chirho = CapabilityChirho::NetChirho {
        allowlist_chirho: allowlist_chirho.to_vec(),
    };
    let admission_chirho =
        crate::blessed_chirho::admit_legacy_operator_effect_chirho(&capability_chirho)?;
    admission_chirho.authorize_chirho(&capability_chirho)?;
    if let Some(prior_chirho) = load_effect_chirho(root_chirho, &idem_key_chirho)? {
        return Ok((prior_chirho, true));
    }
    if !crate::blessed_chirho::is_blessed_chirho(&capability_chirho) {
        return Err(anyhow!(
            "refusing unblessed effect '{}' — effects resolve only through the signed blessed registry",
            crate::blessed_chirho::capability_kind_chirho(&capability_chirho)
        ));
    }
    let response_bytes_chirho = run_net_effect_with_private_headers_chirho(
        root_chirho,
        allowlist_chirho,
        request_bytes_chirho,
        private_headers_chirho,
        true,
        private_body_subject_chirho,
        Some(attribution_chirho),
    )?;
    let signed_request_bytes_chirho =
        net_private_chirho::private_net_logged_request_bytes_chirho(request_bytes_chirho)
            .context("prepare private NetChirho logged request")?;
    let effect_chirho = signed_effect_from_response_chirho(
        root_chirho,
        seq_chirho,
        idem_key_chirho,
        capability_chirho,
        &signed_request_bytes_chirho,
        &response_bytes_chirho,
        // No response policy, so nothing here is stored privately and no source is consulted.
        run_options_chirho::EffectResponseStorageChirho {
            storage_chirho: EffectValueStorageChirho::default(),
            attribution_source_chirho:
                dag_private_value_chirho::RunAttributionSourceChirho::new_chirho(None, None),
        },
    )?;
    Ok((effect_chirho, false))
}

fn run_query_effect_chirho(
    _root_chirho: &Path,
    _capability_prefix_chirho: &str,
    _max_rows_chirho: u64,
    _idem_key_chirho: &HashChirho,
    _request_bytes_chirho: &[u8],
    _request_context_chirho: Option<&RequestContextChirho>,
) -> Result<Vec<u8>> {
    Err(anyhow::Error::new(
        LegacyMoneyRoadRefusedChirho::new_chirho(
            LegacyMoneyRoadChirho::QueryEffectChirho,
            "query_chirho",
        ),
    ))
}

fn query_prefix_within_scope_chirho(scope_chirho: &str, requested_chirho: &str) -> bool {
    if scope_chirho.is_empty() {
        return true;
    }
    if requested_chirho == scope_chirho {
        return true;
    }
    if scope_chirho.ends_with('/') {
        return requested_chirho.starts_with(scope_chirho);
    }
    requested_chirho
        .strip_prefix(scope_chirho)
        .is_some_and(|rest_chirho| rest_chirho.starts_with('/'))
}

fn signed_effect_from_response_chirho(
    root_chirho: &Path,
    seq_chirho: u64,
    idem_key_chirho: HashChirho,
    capability_chirho: CapabilityChirho,
    request_bytes_chirho: &[u8],
    response_bytes_chirho: &[u8],
    response_storage_chirho: run_options_chirho::EffectResponseStorageChirho<'_>,
) -> Result<EffectChirho> {
    let run_options_chirho::EffectResponseStorageChirho {
        storage_chirho,
        attribution_source_chirho,
    } = response_storage_chirho;
    let response_hash_chirho = match storage_chirho.response_storage_chirho {
        Some(policy_chirho) => dag_private_value_chirho::store_dag_value_with_policy_chirho(
            root_chirho,
            response_bytes_chirho,
            &policy_chirho,
            storage_chirho.response_context_chirho,
            None,
            &attribution_source_chirho,
        )?,
        None => cas_chirho::add_chirho(root_chirho, response_bytes_chirho)?,
    };
    let request_hash_chirho = match storage_chirho.request_hash_chirho {
        Some(hash_chirho) => hash_chirho,
        None => cas_chirho::add_chirho(root_chirho, request_bytes_chirho)?,
    };

    let mut effect_chirho = EffectChirho {
        seq_chirho,
        capability_chirho,
        request_chirho: request_hash_chirho,
        idem_key_chirho,
        response_chirho: Some(response_hash_chirho),
        sig_chirho: String::new(),
        at_chirho: now_ms_chirho().to_string(),
    };
    // Sign the effect with the cairn instance key (the signature covers everything but itself).
    let message_chirho = effect_message_chirho(&effect_chirho)?;
    effect_chirho.sig_chirho = signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;

    store_effect_chirho(root_chirho, &effect_chirho)?;
    Ok(effect_chirho)
}

pub fn signed_skipped_effect_chirho(
    root_chirho: &Path,
    idem_key_chirho: HashChirho,
    capability_chirho: CapabilityChirho,
    request_hash_chirho: &HashChirho,
    response_hash_chirho: &HashChirho,
) -> Result<EffectChirho> {
    if let Some(prior_chirho) = load_effect_chirho(root_chirho, &idem_key_chirho)? {
        return Ok(prior_chirho);
    }
    if !crate::blessed_chirho::is_blessed_chirho(&capability_chirho) {
        bail!(
            "refusing to log skipped unblessed effect '{}'",
            crate::blessed_chirho::capability_kind_chirho(&capability_chirho)
        );
    }
    let mut effect_chirho = EffectChirho {
        seq_chirho: 0,
        capability_chirho,
        request_chirho: request_hash_chirho.clone(),
        idem_key_chirho,
        response_chirho: Some(response_hash_chirho.clone()),
        sig_chirho: String::new(),
        at_chirho: now_ms_chirho().to_string(),
    };
    let message_chirho = effect_message_chirho(&effect_chirho)?;
    effect_chirho.sig_chirho = signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
    store_effect_chirho(root_chirho, &effect_chirho)?;
    Ok(effect_chirho)
}

/// The invoked node runs under the invoking run's attribution source, so an anonymous app run's
/// declaration reaches the target's private values too.
fn run_invoke_effect_chirho(
    root_chirho: &Path,
    target_node_chirho: &HashChirho,
    request_bytes_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    attribution_source_chirho: dag_private_value_chirho::RunAttributionSourceChirho<'_>,
) -> Result<Vec<u8>> {
    let _guard_chirho = enter_invoke_chirho()?;
    run_invoke_effect_inner_chirho(
        root_chirho,
        target_node_chirho,
        request_bytes_chirho,
        request_context_chirho,
        attribution_source_chirho,
    )
}

fn enter_invoke_chirho() -> Result<InvokeGuardChirho> {
    let entered_chirho = INVOKE_DEPTH_CHIRHO.with(|depth_chirho| {
        let current_chirho = depth_chirho.get();
        if current_chirho >= MAX_INVOKE_DEPTH_CHIRHO {
            return false;
        }
        if current_chirho == 0 {
            INVOKE_FUEL_REMAINING_CHIRHO.with(|fuel_chirho| {
                fuel_chirho.set(MAX_INVOKE_TOTAL_FUEL_CHIRHO);
            });
        }
        depth_chirho.set(current_chirho + 1);
        true
    });
    if !entered_chirho {
        bail!("InvokeChirho recursion depth exceeded {MAX_INVOKE_DEPTH_CHIRHO}");
    }
    Ok(InvokeGuardChirho)
}

fn reserve_invoke_fuel_chirho(target_fuel_limit_chirho: u64) -> Result<()> {
    INVOKE_FUEL_REMAINING_CHIRHO.with(|fuel_chirho| {
        let remaining_chirho = fuel_chirho.get();
        if target_fuel_limit_chirho > remaining_chirho {
            bail!(
                "InvokeChirho target fuel limit {target_fuel_limit_chirho} exceeds remaining nested invoke budget {remaining_chirho}"
            );
        }
        Ok(())
    })
}

fn spend_invoke_fuel_chirho(fuel_used_chirho: u64) -> Result<()> {
    INVOKE_FUEL_REMAINING_CHIRHO.with(|fuel_chirho| {
        let remaining_chirho = fuel_chirho.get();
        if fuel_used_chirho > remaining_chirho {
            bail!(
                "InvokeChirho target used {fuel_used_chirho} fuel after only {remaining_chirho} remained"
            );
        }
        fuel_chirho.set(remaining_chirho - fuel_used_chirho);
        Ok(())
    })
}

fn run_invoke_effect_inner_chirho(
    root_chirho: &Path,
    target_node_chirho: &HashChirho,
    request_bytes_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    attribution_source_chirho: dag_private_value_chirho::RunAttributionSourceChirho<'_>,
) -> Result<Vec<u8>> {
    let target_def_chirho: crate::model_chirho::NodeDefChirho =
        store_chirho::get_object_chirho(root_chirho, target_node_chirho)
            .with_context(|| format!("load InvokeChirho target node {}", target_node_chirho.0))?;
    if native_worker_chirho::native_node_spec_from_impl_chirho(&target_def_chirho.impl_wasm_chirho)
        .is_some()
    {
        bail!(
            "InvokeChirho target '{}' is a native node; native InvokeChirho targets are not supported yet",
            target_node_chirho.0
        );
    }
    preflight_effect_request_chirho(&target_def_chirho.capabilities_chirho, request_bytes_chirho)?;
    let input_hash_chirho = cas_chirho::add_chirho(root_chirho, request_bytes_chirho)?;
    let (target_result_chirho, cached_chirho) = if target_def_chirho.is_pure_chirho() {
        reserve_invoke_fuel_chirho(target_def_chirho.fuel_limit_chirho)?;
        let wasm_chirho = cas_chirho::get_chirho(root_chirho, &target_def_chirho.impl_wasm_chirho)
            .with_context(|| format!("load InvokeChirho target wasm {}", target_node_chirho.0))?;
        let result_chirho = cache_chirho::run_node_bytes_cached_chirho(
            root_chirho,
            &target_def_chirho,
            target_node_chirho,
            &wasm_chirho,
            &input_hash_chirho,
            &[],
        )?;
        spend_invoke_fuel_chirho(result_chirho.0.fuel_used_chirho)?;
        result_chirho
    } else {
        let mut resolver_chirho =
            dag_private_value_chirho::PrivateDagValueResolverChirho::default();
        cache_chirho::run_effect_node_cached_with_context_and_value_storage_chirho(
            root_chirho,
            &target_def_chirho,
            target_node_chirho,
            &input_hash_chirho,
            &[],
            request_context_chirho,
            cache_chirho::CachedValueStorageChirho {
                resolver_chirho: &mut resolver_chirho,
                output_storage_chirho:
                    &dag_private_value_chirho::ValueStoragePolicyChirho::PublicCasChirho,
                attribution_source_chirho,
            },
        )?
    };
    let payload_hash_chirho = target_result_chirho
        .outputs_chirho
        .values()
        .next()
        .cloned()
        .ok_or_else(|| anyhow!("InvokeChirho target produced no output"))?;
    let _payload_chirho =
        cas_chirho::get_chirho(root_chirho, &payload_hash_chirho).with_context(|| {
            format!(
                "InvokeChirho target payload {} missing",
                payload_hash_chirho.0
            )
        })?;
    serde_json::to_vec(&InvokeResponseChirho {
        target_node_chirho: target_node_chirho.clone(),
        target_run_chirho: target_result_chirho.run_chirho,
        payload_hash_chirho,
        cached_chirho,
    })
    .context("encode InvokeResponseChirho")
}

fn run_net_effect_chirho(
    root_chirho: &Path,
    allowlist_chirho: &[String],
    request_bytes_chirho: &[u8],
) -> Result<Vec<u8>> {
    // Plain NetChirho still persists request/response bodies as normal CAS node I/O. Do not use it
    // for arbitrary free-text or private payloads until the private-body mode is generalized.
    run_net_effect_with_private_headers_chirho(
        root_chirho,
        allowlist_chirho,
        request_bytes_chirho,
        &BTreeMap::new(),
        false,
        None,
        // Plain NetChirho never stores a body privately, so it carries no attribution.
        None,
    )
}

fn run_net_effect_with_private_headers_chirho(
    root_chirho: &Path,
    allowlist_chirho: &[String],
    request_bytes_chirho: &[u8],
    private_headers_chirho: &BTreeMap<String, String>,
    require_success_status_chirho: bool,
    private_body_subject_chirho: Option<&str>,
    attribution_chirho: Option<&crate::privacy_chirho::PrivateBlobAttributionChirho>,
) -> Result<Vec<u8>> {
    let validated_chirho = validate_net_request_chirho(allowlist_chirho, request_bytes_chirho)?;
    let request_chirho = validated_chirho.request_chirho;
    let method_chirho = validated_chirho.method_chirho;
    let url_chirho = validated_chirho.url_chirho;
    let body_chirho = validated_chirho.body_chirho;
    let timeout_ms_chirho = validated_chirho.timeout_ms_chirho;
    let max_response_bytes_chirho = validated_chirho.max_response_bytes_chirho;

    let agent_chirho = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_millis(timeout_ms_chirho))
        .build();
    let mut outbound_chirho = agent_chirho.request(&method_chirho, url_chirho.as_str());
    for (name_chirho, value_chirho) in &request_chirho.headers_chirho {
        outbound_chirho = outbound_chirho.set(name_chirho, value_chirho);
    }
    for (name_chirho, value_chirho) in private_headers_chirho {
        net_private_chirho::validate_private_net_header_chirho(name_chirho, value_chirho)?;
        outbound_chirho = outbound_chirho.set(name_chirho, value_chirho);
    }

    let started_chirho = Instant::now();
    let result_chirho = if method_chirho == "GET" {
        outbound_chirho.call()
    } else {
        outbound_chirho.send_bytes(&body_chirho)
    };
    let response_chirho = match result_chirho {
        Ok(response_chirho) => response_chirho,
        Err(ureq::Error::Status(_, response_chirho)) => response_chirho,
        Err(error_chirho) => bail!("NetChirho request failed: {error_chirho}"),
    };
    let status_chirho = response_chirho.status();
    let content_type_chirho = response_chirho
        .header("content-type")
        .map(|value_chirho| value_chirho.to_string());
    let mut response_body_chirho = Vec::new();
    response_chirho
        .into_reader()
        .take((max_response_bytes_chirho + 1) as u64)
        .read_to_end(&mut response_body_chirho)
        .context("read NetChirho response body")?;
    if response_body_chirho.len() > max_response_bytes_chirho {
        bail!(
            "NetChirho response exceeded byte budget of {}",
            max_response_bytes_chirho
        );
    }
    net_private_chirho::validate_private_net_response_body_chirho(
        &response_body_chirho,
        private_headers_chirho,
    )?;
    if require_success_status_chirho && !(200..300).contains(&status_chirho) {
        bail!("private NetChirho request failed with status {status_chirho}");
    }

    let body_persistence_chirho = net_private_chirho::persist_net_bodies_chirho(
        root_chirho,
        &body_chirho,
        &response_body_chirho,
        private_headers_chirho,
        private_body_subject_chirho,
        attribution_chirho,
    )?;
    let response_chirho = NetResponseChirho {
        status_chirho,
        url_chirho: url_chirho.to_string(),
        content_type_chirho,
        request_bytes_chirho: request_bytes_chirho.len() as u64,
        request_body_bytes_chirho: body_chirho.len() as u64,
        response_body_bytes_chirho: response_body_chirho.len() as u64,
        elapsed_ms_chirho: started_chirho.elapsed().as_millis() as u64,
        request_body_hash_chirho: body_persistence_chirho.request_body_hash_chirho,
        response_body_hash_chirho: body_persistence_chirho.response_body_hash_chirho,
        request_body_private_ref_chirho: body_persistence_chirho.request_body_private_ref_chirho,
        response_body_private_ref_chirho: body_persistence_chirho.response_body_private_ref_chirho,
        body_base64_chirho: body_persistence_chirho.body_base64_chirho,
    };
    serde_json::to_vec(&response_chirho).context("encode NetResponseChirho")
}

fn validate_net_request_chirho(
    allowlist_chirho: &[String],
    request_bytes_chirho: &[u8],
) -> Result<ValidatedNetRequestChirho> {
    if request_bytes_chirho.len() > MAX_NET_REQUEST_BYTES_CHIRHO {
        bail!(
            "NetChirho request exceeds {} bytes",
            MAX_NET_REQUEST_BYTES_CHIRHO
        );
    }
    let request_chirho: NetRequestChirho =
        serde_json::from_slice(request_bytes_chirho).context("decode NetRequestChirho")?;
    let method_chirho = request_chirho.method_chirho.trim().to_ascii_uppercase();
    let url_chirho = Url::parse(&request_chirho.url_chirho)
        .with_context(|| format!("parse NetChirho url '{}'", request_chirho.url_chirho))?;
    validate_net_target_url_chirho(&url_chirho)?;
    if !net_url_allowed_chirho(allowlist_chirho, &url_chirho)? {
        bail!(
            "NetChirho url '{}' is outside the capability allowlist",
            request_chirho.url_chirho
        );
    }

    let timeout_ms_chirho = request_chirho
        .timeout_ms_chirho
        .unwrap_or(DEFAULT_NET_TIMEOUT_MS_CHIRHO);
    if timeout_ms_chirho == 0 || timeout_ms_chirho > MAX_NET_TIMEOUT_MS_CHIRHO {
        bail!(
            "NetChirho timeout_ms_chirho must be 1..={}",
            MAX_NET_TIMEOUT_MS_CHIRHO
        );
    }
    let max_response_bytes_chirho = request_chirho
        .max_response_bytes_chirho
        .unwrap_or(DEFAULT_NET_RESPONSE_BYTES_CHIRHO);
    if max_response_bytes_chirho > MAX_NET_RESPONSE_BYTES_CHIRHO {
        bail!(
            "NetChirho max_response_bytes_chirho must be <= {}",
            MAX_NET_RESPONSE_BYTES_CHIRHO
        );
    }

    let body_chirho = match request_chirho.body_base64_chirho.as_deref() {
        Some(body_chirho) => BASE64_CHIRHO
            .decode(body_chirho)
            .context("decode NetChirho body_base64_chirho")?,
        None => Vec::new(),
    };
    if body_chirho.len() > MAX_NET_REQUEST_BYTES_CHIRHO {
        bail!(
            "NetChirho request body exceeds {} bytes",
            MAX_NET_REQUEST_BYTES_CHIRHO
        );
    }
    if method_chirho == "GET" && !body_chirho.is_empty() {
        bail!("NetChirho GET requests cannot carry a body");
    }
    if method_chirho != "GET" && method_chirho != "POST" {
        bail!("NetChirho supports GET and POST only in M30.1");
    }

    for (name_chirho, value_chirho) in &request_chirho.headers_chirho {
        validate_net_header_chirho(name_chirho, value_chirho)?;
    }
    Ok(ValidatedNetRequestChirho {
        request_chirho,
        method_chirho,
        url_chirho,
        body_chirho,
        timeout_ms_chirho,
        max_response_bytes_chirho,
    })
}

fn validate_net_target_url_chirho(url_chirho: &Url) -> Result<()> {
    if !matches!(url_chirho.scheme(), "http" | "https") {
        bail!("NetChirho supports http and https urls only");
    }
    if url_chirho.host_str().is_none() {
        bail!("NetChirho url must include a host");
    }
    if !url_chirho.username().is_empty() || url_chirho.password().is_some() {
        bail!("NetChirho urls must not contain credentials");
    }
    if url_chirho.fragment().is_some() {
        bail!("NetChirho urls must not contain fragments");
    }
    if let Some(host_chirho) = url_chirho.host_str() {
        if let Ok(ip_chirho) = host_chirho.parse::<IpAddr>() {
            validate_net_literal_ip_chirho(ip_chirho)?;
        }
    }
    Ok(())
}

fn validate_net_literal_ip_chirho(ip_chirho: IpAddr) -> Result<()> {
    match ip_chirho {
        IpAddr::V4(ip_chirho)
            if ip_chirho.is_private()
                || ip_chirho.is_link_local()
                || ip_chirho.is_unspecified()
                || ip_chirho.is_broadcast() =>
        {
            bail!("NetChirho refuses literal private/link-local IPv4 targets")
        }
        IpAddr::V6(ip_chirho)
            if ip_chirho.is_unique_local()
                || ip_chirho.is_unicast_link_local()
                || ip_chirho.is_unspecified() =>
        {
            bail!("NetChirho refuses literal private/link-local IPv6 targets")
        }
        _ => Ok(()),
    }
}

fn net_url_allowed_chirho(allowlist_chirho: &[String], target_chirho: &Url) -> Result<bool> {
    if allowlist_chirho.is_empty() {
        bail!("NetChirho capability has an empty allowlist");
    }
    for allowed_chirho in allowlist_chirho {
        let allowed_url_chirho = Url::parse(allowed_chirho)
            .with_context(|| format!("parse NetChirho allowlist url '{allowed_chirho}'"))?;
        validate_net_target_url_chirho(&allowed_url_chirho)?;
        if allowed_url_chirho.query().is_some() || allowed_url_chirho.fragment().is_some() {
            bail!("NetChirho allowlist entries must not contain query strings or fragments");
        }
        if allowed_url_chirho.scheme() == target_chirho.scheme()
            && allowed_url_chirho.host_str() == target_chirho.host_str()
            && allowed_url_chirho.port_or_known_default() == target_chirho.port_or_known_default()
            && net_path_prefix_matches_chirho(allowed_url_chirho.path(), target_chirho.path())
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn net_path_prefix_matches_chirho(allowed_path_chirho: &str, target_path_chirho: &str) -> bool {
    let allowed_path_chirho = if allowed_path_chirho.is_empty() {
        "/"
    } else {
        allowed_path_chirho
    };
    if allowed_path_chirho == "/" {
        return true;
    }
    target_path_chirho == allowed_path_chirho
        || target_path_chirho
            .strip_prefix(allowed_path_chirho)
            .is_some_and(|remaining_chirho| remaining_chirho.starts_with('/'))
}

fn validate_net_header_chirho(name_chirho: &str, value_chirho: &str) -> Result<()> {
    let lower_chirho = name_chirho.to_ascii_lowercase();
    if name_chirho.is_empty() {
        bail!("NetChirho header names must not be empty");
    }
    if !SAFE_NET_HEADERS_CHIRHO.contains(&lower_chirho.as_str()) {
        bail!(
            "NetChirho header '{}' is not safe for immutable logging; use a later SecretRefChirho integration for secret-bearing headers",
            name_chirho
        );
    }
    if !name_chirho
        .bytes()
        .all(|byte_chirho| byte_chirho.is_ascii_alphanumeric() || byte_chirho == b'-')
    {
        bail!("NetChirho header names must be ASCII token names");
    }
    if value_chirho.contains('\r') || value_chirho.contains('\n') {
        bail!("NetChirho header values must not contain CR/LF");
    }
    if value_chirho.len() > 4096 {
        bail!("NetChirho header values must be <= 4096 bytes");
    }
    Ok(())
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

/// A non-cryptographic PRNG (splitmix64 seeded from the clock). v1 only — the value is
/// *recorded*, so it must be unpredictable once, not crypto-grade.
fn random_u64_chirho() -> u64 {
    let seed_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_nanos() as u64)
        .unwrap_or(0);
    let mut z_chirho = seed_chirho.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z_chirho = (z_chirho ^ (z_chirho >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z_chirho = (z_chirho ^ (z_chirho >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z_chirho ^ (z_chirho >> 31)
}

/// Read the existing cairn instance public key without creating a new signing key.
pub fn existing_pubkey_hex_chirho(root_chirho: &Path) -> Result<String> {
    signer_chirho::existing_pubkey_hex_chirho(root_chirho)
}

pub(crate) fn derive_instance_key_chirho(
    root_chirho: &Path,
    context_chirho: &str,
) -> Result<[u8; 32]> {
    signer_chirho::derive_instance_key_chirho(root_chirho, context_chirho)
}

fn effect_message_chirho(effect_chirho: &EffectChirho) -> Result<Vec<u8>> {
    effect_signing_message_chirho(effect_chirho).context("encode effect sig payload")
}

#[derive(Serialize)]
struct VolatileEffectRecordSigPayloadChirho<'a> {
    schema_chirho: &'a str,
    seq_chirho: u64,
    effect_chirho: &'a EffectChirho,
}

fn volatile_effect_record_message_chirho(
    record_chirho: &VolatileEffectRecordChirho,
) -> Result<Vec<u8>> {
    let payload_chirho = VolatileEffectRecordSigPayloadChirho {
        schema_chirho: &record_chirho.schema_chirho,
        seq_chirho: record_chirho.seq_chirho,
        effect_chirho: &record_chirho.effect_chirho,
    };
    serde_json::to_vec(&payload_chirho).context("encode volatile effect record sig payload")
}

/// Verify an effect's signature against the instance verifying key. Errors on a bad or
/// tampered signature — this is the tamper-evidence checked on load.
pub fn verify_effect_chirho(root_chirho: &Path, effect_chirho: &EffectChirho) -> Result<()> {
    let message_chirho = effect_message_chirho(effect_chirho)?;
    let valid_chirho = signer_chirho::verify_with_root_pubkey_chirho(
        root_chirho,
        &message_chirho,
        &effect_chirho.sig_chirho,
    )?;
    if !valid_chirho {
        bail!(
            "effect {} failed signature verification (tamper?)",
            effect_chirho.idem_key_chirho.0
        );
    }
    Ok(())
}

pub fn verify_volatile_effect_record_chirho(
    root_chirho: &Path,
    record_chirho: &VolatileEffectRecordChirho,
) -> Result<()> {
    if record_chirho.schema_chirho != VOLATILE_EFFECT_RECORD_SCHEMA_CHIRHO {
        bail!(
            "volatile effect record schema '{}' is not supported",
            record_chirho.schema_chirho
        );
    }
    if !is_volatile_chirho(&record_chirho.effect_chirho.capability_chirho) {
        bail!(
            "volatile effect record seq {} contains non-volatile capability",
            record_chirho.seq_chirho
        );
    }
    verify_effect_chirho(root_chirho, &record_chirho.effect_chirho)?;
    let message_chirho = volatile_effect_record_message_chirho(record_chirho)?;
    let valid_chirho = signer_chirho::verify_with_root_pubkey_chirho(
        root_chirho,
        &message_chirho,
        &record_chirho.sig_chirho,
    )?;
    if !valid_chirho {
        bail!(
            "volatile effect record seq {} failed signature verification (tamper?)",
            record_chirho.seq_chirho
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "effect_chirho/tests_chirho.rs"]
mod tests_chirho;

#[cfg(test)]
#[path = "effect_chirho/store_seal_door_tests_chirho.rs"]
mod store_seal_door_tests_chirho;

#[cfg(test)]
#[path = "effect_chirho/store_seal_read_path_tests_chirho.rs"]
mod store_seal_read_path_tests_chirho;
