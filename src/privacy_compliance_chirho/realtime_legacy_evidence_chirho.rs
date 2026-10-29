// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Read-only legacy realtime evidence: the session/event/epilogue record types, JSONL loads,
//! and the verify/reveal evidence family retained for historical subject-export/compliance/
//! privacy evidence after the legacy realtime money protocol closed typed (road five of the
//! one law) ahead of its runtime deletion at CF6 wave-1 (#5482-#5487 three-seat disposition).
//! Slice 2: every legacy-ledger cross-check sits behind the injected
//! `RealtimeLegacyLedgerViewChirho` - `Some` preserves the full ledger binding byte-for-byte;
//! `None` skips only that binding while signatures, sequence density, arithmetic, conservation,
//! and privacy-subject checks stay enforced. No writer, no session lifecycle, no ledger dependency
//! lives here.
//!
//! **CORRECTED AT CF6 WAVE-1.** This sentence used to read "`None` (post-wave-1 roots)", which was
//! true when written and stopped being true without anyone editing it: slice 2 (`ab1f5b81`) bound
//! the view to the two-road dispatcher that dies with the spine, then the (a2-1) probe rebase
//! (`0ef98b63`) repointed it onto `verified_entries_single_road_chirho`, which SURVIVES wave-1. The
//! injection now lives in `realtime_ledger_bound_evidence_chirho`, so the documented degradation
//! never arrives — post-wave-1 callers still pass `Some`. A doc describing a safety degradation
//! that has silently stopped happening is the dangerous direction of stale: it invites a future
//! reader to "simplify" the wrappers to `None` and lose a verified source from subject export while
//! every test on an intact corpus stays green. `None` remains supported for roots with no ledger at
//! all; it is no longer anybody's plan.

use crate::model_chirho::{
    CapabilityChirho, DagChirho, EdgeChirho, HashChirho, NodeDefChirho, RunKeyChirho,
    RunStatusChirho,
};
use crate::{
    app_chirho, cache_chirho, cas_chirho, display_chirho, privacy_chirho, store_chirho,
    verify_chirho,
};
use anyhow::{anyhow, bail, Context, Result};
use cairn_signer_chirho::signer_chirho;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RealtimeSessionStatusChirho {
    OpenChirho,
    ClosedChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RealtimeEventKindChirho {
    UserSpokeChirho,
    LlmRespondedChirho,
    BillTickChirho,
    ProviderUsageChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealtimeSessionRecordChirho {
    pub seq_chirho: u64,
    pub session_id_chirho: String,
    pub capability_chirho: CapabilityChirho,
    pub app_chirho: String,
    pub caller_chirho: String,
    pub payer_chirho: String,
    pub provider_account_chirho: String,
    pub reserve_account_chirho: String,
    pub max_seconds_chirho: u64,
    pub token_per_second_chirho: i64,
    pub authorized_token_chirho: i64,
    pub reserve_ledger_seq_chirho: u64,
    pub status_chirho: RealtimeSessionStatusChirho,
    pub duration_seconds_chirho: u64,
    pub billed_seconds_chirho: u64,
    pub settled_token_chirho: i64,
    pub released_token_chirho: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_ledger_seq_chirho: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_chirho: Option<HashChirho>,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealtimeEventRecordChirho {
    pub seq_chirho: u64,
    pub session_id_chirho: String,
    pub kind_chirho: RealtimeEventKindChirho,
    pub payload_chirho: privacy_chirho::PrivateBlobRefChirho,
    pub billable_seconds_chirho: u64,
    pub amount_token_chirho: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ledger_seq_chirho: Option<u64>,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealtimeTranscriptArtifactChirho {
    pub session_id_chirho: String,
    pub app_chirho: String,
    pub caller_chirho: String,
    pub provider_account_chirho: String,
    pub duration_seconds_chirho: u64,
    pub billed_seconds_chirho: u64,
    pub settled_token_chirho: i64,
    pub released_token_chirho: i64,
    pub transcript_blob_chirho: privacy_chirho::PrivateBlobRefChirho,
    pub event_payloads_chirho: Vec<privacy_chirho::PrivateBlobRefChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealtimeTranscriptRevealChirho {
    pub session_id_chirho: String,
    pub artifact_chirho: HashChirho,
    pub transcript_blob_chirho: privacy_chirho::PrivateBlobRefChirho,
    pub access_record_chirho: privacy_chirho::PrivacyAccessRecordChirho,
    pub plaintext_chirho: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealtimeEpilogueInputChirho {
    pub session_id_chirho: String,
    pub app_chirho: String,
    pub caller_chirho: String,
    pub provider_account_chirho: String,
    pub artifact_chirho: HashChirho,
    pub close_seq_chirho: u64,
    pub duration_seconds_chirho: u64,
    pub billed_seconds_chirho: u64,
    pub settled_token_chirho: i64,
    pub released_token_chirho: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_ledger_seq_chirho: Option<u64>,
    pub transcript_blob_chirho: privacy_chirho::PrivateBlobRefChirho,
    pub event_payloads_chirho: Vec<privacy_chirho::PrivateBlobRefChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealtimeEpilogueNodeRunChirho {
    pub node_name_chirho: String,
    pub node_chirho: HashChirho,
    pub run_chirho: HashChirho,
    pub cached_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealtimeEpilogueRecordChirho {
    pub seq_chirho: u64,
    pub session_id_chirho: String,
    pub app_chirho: String,
    pub caller_chirho: String,
    pub artifact_chirho: HashChirho,
    pub dag_chirho: HashChirho,
    pub input_hash_chirho: HashChirho,
    pub sink_run_chirho: HashChirho,
    pub payload_hash_chirho: HashChirho,
    pub node_runs_chirho: Vec<RealtimeEpilogueNodeRunChirho>,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

pub type RealtimeDisplayRecordChirho<T> = display_chirho::DisplayRecordChirho<T>;
pub type RealtimeSessionDisplayRecordChirho =
    RealtimeDisplayRecordChirho<RealtimeSessionRecordChirho>;
pub type RealtimeEventDisplayRecordChirho = RealtimeDisplayRecordChirho<RealtimeEventRecordChirho>;
pub type RealtimeEpilogueDisplayRecordChirho =
    RealtimeDisplayRecordChirho<RealtimeEpilogueRecordChirho>;

pub fn sessions_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("realtime-sessions-chirho.jsonl")
}

pub fn events_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("realtime-events-chirho.jsonl")
}

pub fn epilogues_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("realtime-epilogues-chirho.jsonl")
}

pub fn load_realtime_sessions_chirho(
    root_chirho: &Path,
) -> Result<Vec<RealtimeSessionRecordChirho>> {
    load_jsonl_chirho(&sessions_path_chirho(root_chirho))
}

pub fn load_realtime_events_chirho(root_chirho: &Path) -> Result<Vec<RealtimeEventRecordChirho>> {
    load_jsonl_chirho(&events_path_chirho(root_chirho))
}

pub fn load_realtime_epilogues_chirho(
    root_chirho: &Path,
) -> Result<Vec<RealtimeEpilogueRecordChirho>> {
    load_jsonl_chirho(&epilogues_path_chirho(root_chirho))
}

pub(crate) fn load_jsonl_chirho<T: DeserializeOwned>(path_chirho: &Path) -> Result<Vec<T>> {
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut out_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        out_chirho.push(serde_json::from_str(line_chirho)?);
    }
    Ok(out_chirho)
}

pub const REALTIME_TRANSCRIPT_REVEAL_PURPOSE_CHIRHO: &str = "realtime-transcript-reveal-chirho";
pub(crate) const REALTIME_SESSION_ID_MAX_CHIRHO: usize = 96;
const REALTIME_ACCOUNT_MAX_CHIRHO: usize = 160;

/// One legacy-ledger entry assertion injected into the evidence verifiers. The pre-regenesis
/// realtime protocol cross-checked its signed records against root ledger entries, and that
/// store dies with the money spine at CF6 wave-1: `Some` (the dying realtime wrapper)
/// preserves the full cross-check byte-for-byte, `None` (fresh or post-wave-1 roots) skips
/// only the ledger binding while every record-shape law stays enforced.
pub trait RealtimeLegacyLedgerViewChirho {
    fn assert_entry_chirho(
        &self,
        seq_chirho: u64,
        memo_prefix_chirho: &str,
        postings_chirho: &[RealtimeLegacyPostingChirho],
    ) -> Result<()>;
}

/// Module-local posting shape for the injected view: every legacy realtime posting is in the
/// token asset, so account plus signed token amount is the whole coordinate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealtimeLegacyPostingChirho {
    pub account_chirho: String,
    pub amount_token_chirho: i64,
}

pub fn realtime_session_capability_chirho(
    app_chirho: &str,
    caller_chirho: &str,
) -> CapabilityChirho {
    CapabilityChirho::RealtimeSessionChirho {
        app_chirho: app_chirho.to_string(),
        caller_chirho: caller_chirho.to_string(),
    }
}

pub fn realtime_transcript_row_key_chirho(session_id_chirho: &str) -> Result<String> {
    validate_session_id_chirho(session_id_chirho)?;
    Ok(format!("realtime-session/{session_id_chirho}/transcript"))
}

#[derive(Clone, Debug, Default)]
pub struct RealtimeUsageChirho {
    pub billable_seconds_chirho: u64,
    pub amount_token_chirho: i64,
}

pub fn realtime_usage_from_events_chirho(
    events_chirho: &[RealtimeEventRecordChirho],
) -> BTreeMap<String, RealtimeUsageChirho> {
    let mut out_chirho = BTreeMap::new();
    for event_chirho in events_chirho {
        if event_chirho.kind_chirho != RealtimeEventKindChirho::BillTickChirho {
            continue;
        }
        let usage_chirho = out_chirho
            .entry(event_chirho.session_id_chirho.clone())
            .or_insert_with(RealtimeUsageChirho::default);
        usage_chirho.billable_seconds_chirho += event_chirho.billable_seconds_chirho;
        usage_chirho.amount_token_chirho += event_chirho.amount_token_chirho;
    }
    out_chirho
}

pub fn closed_session_record_chirho(
    root_chirho: &Path,
    session_id_chirho: &str,
) -> Result<Option<RealtimeSessionRecordChirho>> {
    Ok(load_realtime_sessions_chirho(root_chirho)?
        .into_iter()
        .find(|record_chirho| {
            record_chirho.session_id_chirho == session_id_chirho
                && record_chirho.status_chirho == RealtimeSessionStatusChirho::ClosedChirho
        }))
}

pub fn validate_session_record_chirho(record_chirho: &RealtimeSessionRecordChirho) -> Result<()> {
    validate_session_id_chirho(&record_chirho.session_id_chirho)?;
    app_chirho::validate_app_name_chirho(&record_chirho.app_chirho)?;
    validate_realtime_account_chirho("caller_chirho", &record_chirho.caller_chirho)?;
    validate_realtime_account_chirho("payer_chirho", &record_chirho.payer_chirho)?;
    validate_realtime_provider_account_chirho(&record_chirho.provider_account_chirho)?;
    validate_realtime_account_chirho(
        "reserve_account_chirho",
        &record_chirho.reserve_account_chirho,
    )?;
    if record_chirho.capability_chirho
        != realtime_session_capability_chirho(
            &record_chirho.app_chirho,
            &record_chirho.caller_chirho,
        )
    {
        bail!("realtime session capability does not match app/caller");
    }
    if record_chirho.max_seconds_chirho == 0 {
        bail!("max_seconds_chirho must be positive");
    }
    if record_chirho.token_per_second_chirho <= 0 {
        bail!("token_per_second_chirho must be positive");
    }
    if record_chirho.authorized_token_chirho
        != authorized_token_chirho(
            record_chirho.max_seconds_chirho,
            record_chirho.token_per_second_chirho,
        )?
    {
        bail!("realtime authorized token mismatch");
    }
    match record_chirho.status_chirho {
        RealtimeSessionStatusChirho::OpenChirho => {
            if record_chirho.duration_seconds_chirho != 0
                || record_chirho.billed_seconds_chirho != 0
                || record_chirho.settled_token_chirho != 0
                || record_chirho.released_token_chirho != 0
                || record_chirho.settlement_ledger_seq_chirho.is_some()
                || record_chirho.transcript_chirho.is_some()
            {
                bail!("open realtime session carries close fields");
            }
        }
        RealtimeSessionStatusChirho::ClosedChirho => {
            if record_chirho.billed_seconds_chirho > record_chirho.max_seconds_chirho {
                bail!("closed realtime session exceeds max seconds");
            }
            let expected_settled_chirho = amount_for_seconds_chirho(
                record_chirho.billed_seconds_chirho,
                record_chirho.token_per_second_chirho,
            )?;
            if record_chirho.settled_token_chirho != expected_settled_chirho {
                bail!("closed realtime session settled token mismatch");
            }
            if record_chirho.settled_token_chirho + record_chirho.released_token_chirho
                != record_chirho.authorized_token_chirho
            {
                bail!("closed realtime session does not settle/release full authorization");
            }
            if record_chirho.transcript_chirho.is_none() {
                bail!("closed realtime session missing transcript artifact");
            }
        }
    }
    Ok(())
}

pub fn validate_event_record_chirho(record_chirho: &RealtimeEventRecordChirho) -> Result<()> {
    validate_session_id_chirho(&record_chirho.session_id_chirho)?;
    match record_chirho.kind_chirho {
        RealtimeEventKindChirho::UserSpokeChirho | RealtimeEventKindChirho::LlmRespondedChirho => {
            if record_chirho.billable_seconds_chirho != 0
                || record_chirho.amount_token_chirho != 0
                || record_chirho.ledger_seq_chirho.is_some()
            {
                bail!("non-billing realtime event carries billing fields");
            }
        }
        RealtimeEventKindChirho::BillTickChirho => {
            if record_chirho.billable_seconds_chirho == 0
                || record_chirho.amount_token_chirho <= 0
                || record_chirho.ledger_seq_chirho.is_none()
            {
                bail!("bill tick realtime event missing billing fields");
            }
        }
        RealtimeEventKindChirho::ProviderUsageChirho => {
            if record_chirho.billable_seconds_chirho == 0
                || record_chirho.amount_token_chirho <= 0
                || record_chirho.ledger_seq_chirho.is_some()
            {
                bail!("provider usage realtime event must carry observed seconds and amount without ledger seq");
            }
        }
    }
    Ok(())
}

pub fn validate_session_id_chirho(session_id_chirho: &str) -> Result<()> {
    validate_nonempty_chirho("session_id_chirho", session_id_chirho)?;
    if session_id_chirho.len() > REALTIME_SESSION_ID_MAX_CHIRHO {
        bail!("session_id_chirho is too long");
    }
    if !session_id_chirho.bytes().all(|byte_chirho| {
        byte_chirho.is_ascii_alphanumeric() || matches!(byte_chirho, b'-' | b'_')
    }) {
        bail!("session_id_chirho must use only ascii letters, digits, '-' or '_'");
    }
    Ok(())
}

pub fn validate_realtime_provider_account_chirho(provider_account_chirho: &str) -> Result<()> {
    validate_realtime_account_chirho("provider_account_chirho", provider_account_chirho)?;
    if !provider_account_chirho.starts_with("provider/") {
        bail!("provider_account_chirho must be in the provider/ namespace");
    }
    Ok(())
}

pub fn validate_realtime_account_chirho(name_chirho: &str, value_chirho: &str) -> Result<()> {
    validate_nonempty_chirho(name_chirho, value_chirho)?;
    if value_chirho.len() > REALTIME_ACCOUNT_MAX_CHIRHO {
        bail!("{name_chirho} is too long");
    }
    if value_chirho.starts_with('/')
        || value_chirho.ends_with('/')
        || value_chirho.contains("//")
        || value_chirho.contains("..")
        || value_chirho.contains('\\')
        || value_chirho.contains('@')
        || value_chirho.chars().any(char::is_whitespace)
        || !value_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_alphanumeric() || matches!(byte_chirho, b'/' | b'-' | b'_' | b'.')
        })
    {
        bail!("{name_chirho} must be bounded safe account text");
    }
    Ok(())
}

pub fn validate_nonempty_chirho(name_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.trim().is_empty() {
        bail!("{name_chirho} is required");
    }
    Ok(())
}

pub fn realtime_bill_tick_subject_chirho(session_id_chirho: &str) -> String {
    format!("realtime/{session_id_chirho}/bill-tick")
}

pub fn realtime_event_payload_subject_chirho(
    event_chirho: &RealtimeEventRecordChirho,
    open_chirho: &RealtimeSessionRecordChirho,
) -> String {
    match event_chirho.kind_chirho {
        RealtimeEventKindChirho::BillTickChirho => {
            realtime_bill_tick_subject_chirho(&event_chirho.session_id_chirho)
        }
        RealtimeEventKindChirho::UserSpokeChirho
        | RealtimeEventKindChirho::LlmRespondedChirho
        | RealtimeEventKindChirho::ProviderUsageChirho => open_chirho.caller_chirho.clone(),
    }
}

pub fn validate_realtime_private_blob_ref_subject_chirho(
    root_chirho: &Path,
    context_chirho: &str,
    blob_chirho: &privacy_chirho::PrivateBlobRefChirho,
    expected_subject_chirho: &str,
) -> Result<()> {
    privacy_chirho::verify_private_blob_ref_subject_chirho(
        root_chirho,
        context_chirho,
        blob_chirho,
        expected_subject_chirho,
    )
}

pub fn authorized_token_chirho(
    max_seconds_chirho: u64,
    token_per_second_chirho: i64,
) -> Result<i64> {
    let seconds_chirho =
        i64::try_from(max_seconds_chirho).map_err(|_| anyhow!("max_seconds_chirho exceeds i64"))?;
    seconds_chirho
        .checked_mul(token_per_second_chirho)
        .ok_or_else(|| anyhow!("realtime authorized token overflow"))
}

pub fn amount_for_seconds_chirho(seconds_chirho: u64, token_per_second_chirho: i64) -> Result<i64> {
    let seconds_chirho =
        i64::try_from(seconds_chirho).map_err(|_| anyhow!("seconds_chirho exceeds i64"))?;
    seconds_chirho
        .checked_mul(token_per_second_chirho)
        .ok_or_else(|| anyhow!("realtime amount overflow"))
}

pub fn elapsed_seconds_chirho(start_ms_chirho: u64, end_ms_chirho: u64) -> Result<u64> {
    if end_ms_chirho < start_ms_chirho {
        bail!("realtime signed timestamp moved backward");
    }
    Ok((end_ms_chirho - start_ms_chirho) / 1_000)
}

pub fn session_message_chirho(record_chirho: &RealtimeSessionRecordChirho) -> Result<Vec<u8>> {
    let mut message_chirho = record_chirho.clone();
    message_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&message_chirho)?)
}

pub fn event_message_chirho(record_chirho: &RealtimeEventRecordChirho) -> Result<Vec<u8>> {
    let mut message_chirho = record_chirho.clone();
    message_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&message_chirho)?)
}

pub fn verify_session_signature_chirho(
    root_chirho: &Path,
    record_chirho: &RealtimeSessionRecordChirho,
) -> Result<()> {
    if !signer_chirho::verify_with_pubkey_chirho(
        &signer_chirho::pubkey_hex_chirho(root_chirho)?,
        &session_message_chirho(record_chirho)?,
        &record_chirho.sig_chirho,
    )? {
        bail!(
            "realtime session record #{} signature invalid",
            record_chirho.seq_chirho
        );
    }
    Ok(())
}

pub fn verify_event_signature_chirho(
    root_chirho: &Path,
    record_chirho: &RealtimeEventRecordChirho,
) -> Result<()> {
    if !signer_chirho::verify_with_pubkey_chirho(
        &signer_chirho::pubkey_hex_chirho(root_chirho)?,
        &event_message_chirho(record_chirho)?,
        &record_chirho.sig_chirho,
    )? {
        bail!(
            "realtime event record #{} signature invalid",
            record_chirho.seq_chirho
        );
    }
    Ok(())
}

pub fn verify_realtime_evidence_chirho(
    root_chirho: &Path,
    ledger_view_chirho: Option<&dyn RealtimeLegacyLedgerViewChirho>,
) -> Result<(usize, usize)> {
    let sessions_chirho = load_realtime_sessions_chirho(root_chirho)?;
    let events_chirho = load_realtime_events_chirho(root_chirho)?;
    let mut by_session_chirho: BTreeMap<String, Vec<&RealtimeSessionRecordChirho>> =
        BTreeMap::new();
    let mut seen_session_seq_chirho = BTreeSet::new();
    for (index_chirho, record_chirho) in sessions_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!("realtime session seq gap at index {index_chirho}");
        }
        if !seen_session_seq_chirho.insert(record_chirho.seq_chirho) {
            bail!(
                "duplicate realtime session seq {}",
                record_chirho.seq_chirho
            );
        }
        verify_session_signature_chirho(root_chirho, record_chirho)?;
        validate_session_record_chirho(record_chirho)?;
        by_session_chirho
            .entry(record_chirho.session_id_chirho.clone())
            .or_default()
            .push(record_chirho);
    }
    let mut usage_by_session_chirho: BTreeMap<String, RealtimeUsageChirho> = BTreeMap::new();
    let mut provider_usage_by_session_chirho: BTreeMap<String, RealtimeUsageChirho> =
        BTreeMap::new();
    let mut tick_clock_by_session_chirho: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut seen_event_seq_chirho = BTreeSet::new();
    for (index_chirho, event_chirho) in events_chirho.iter().enumerate() {
        if event_chirho.seq_chirho != index_chirho as u64 {
            bail!("realtime event seq gap at index {index_chirho}");
        }
        if !seen_event_seq_chirho.insert(event_chirho.seq_chirho) {
            bail!("duplicate realtime event seq {}", event_chirho.seq_chirho);
        }
        verify_event_signature_chirho(root_chirho, event_chirho)?;
        validate_event_record_chirho(event_chirho)?;
        let records_for_event_chirho = by_session_chirho
            .get(&event_chirho.session_id_chirho)
            .ok_or_else(|| {
                anyhow!(
                    "realtime event #{} references unknown session '{}'",
                    event_chirho.seq_chirho,
                    event_chirho.session_id_chirho
                )
            })?;
        let open_chirho = records_for_event_chirho
            .iter()
            .find(|record_chirho| {
                record_chirho.status_chirho == RealtimeSessionStatusChirho::OpenChirho
            })
            .ok_or_else(|| anyhow!("realtime event references session without open record"))?;
        let expected_payload_subject_chirho =
            realtime_event_payload_subject_chirho(event_chirho, open_chirho);
        validate_realtime_private_blob_ref_subject_chirho(
            root_chirho,
            &format!("realtime event #{} payload_chirho", event_chirho.seq_chirho),
            &event_chirho.payload_chirho,
            &expected_payload_subject_chirho,
        )?;
        if event_chirho.at_ms_chirho < open_chirho.at_ms_chirho {
            bail!(
                "realtime event #{} predates its open record",
                event_chirho.seq_chirho
            );
        }
        if let Some(close_chirho) = records_for_event_chirho.iter().find(|record_chirho| {
            record_chirho.status_chirho == RealtimeSessionStatusChirho::ClosedChirho
        }) {
            if event_chirho.at_ms_chirho > close_chirho.at_ms_chirho {
                match event_chirho.kind_chirho {
                    RealtimeEventKindChirho::ProviderUsageChirho => {}
                    _ => {
                        bail!(
                            "realtime event #{} postdates its close record",
                            event_chirho.seq_chirho
                        );
                    }
                }
            }
        }
        match event_chirho.kind_chirho {
            RealtimeEventKindChirho::BillTickChirho => {
                let clock_chirho = tick_clock_by_session_chirho
                    .entry(event_chirho.session_id_chirho.clone())
                    .or_insert((open_chirho.at_ms_chirho, 0));
                let elapsed_seconds_chirho =
                    elapsed_seconds_chirho(clock_chirho.0, event_chirho.at_ms_chirho)?;
                let remaining_seconds_chirho = open_chirho
                    .max_seconds_chirho
                    .checked_sub(clock_chirho.1)
                    .ok_or_else(|| anyhow!("realtime tick clock exceeds authorized seconds"))?;
                let expected_seconds_chirho = elapsed_seconds_chirho.min(remaining_seconds_chirho);
                if event_chirho.billable_seconds_chirho != expected_seconds_chirho {
                    bail!(
                        "realtime tick #{} has wrong elapsed seconds",
                        event_chirho.seq_chirho
                    );
                }
                let expected_amount_chirho = amount_for_seconds_chirho(
                    event_chirho.billable_seconds_chirho,
                    open_chirho.token_per_second_chirho,
                )?;
                if expected_amount_chirho != event_chirho.amount_token_chirho {
                    bail!(
                        "realtime tick #{} has wrong amount",
                        event_chirho.seq_chirho
                    );
                }
                let ledger_seq_chirho = event_chirho
                    .ledger_seq_chirho
                    .ok_or_else(|| anyhow!("realtime bill tick missing ledger seq"))?;
                if let Some(view_chirho) = ledger_view_chirho {
                    view_chirho.assert_entry_chirho(
                        ledger_seq_chirho,
                        &format!("realtime bill tick {}", event_chirho.session_id_chirho),
                        &[
                            RealtimeLegacyPostingChirho {
                                account_chirho: open_chirho.reserve_account_chirho.clone(),
                                amount_token_chirho: -event_chirho.amount_token_chirho,
                            },
                            RealtimeLegacyPostingChirho {
                                account_chirho: open_chirho.provider_account_chirho.clone(),
                                amount_token_chirho: event_chirho.amount_token_chirho,
                            },
                        ],
                    )?;
                }
                let usage_chirho = usage_by_session_chirho
                    .entry(event_chirho.session_id_chirho.clone())
                    .or_default();
                usage_chirho.billable_seconds_chirho = usage_chirho
                    .billable_seconds_chirho
                    .checked_add(event_chirho.billable_seconds_chirho)
                    .ok_or_else(|| anyhow!("realtime billable seconds overflow"))?;
                usage_chirho.amount_token_chirho = usage_chirho
                    .amount_token_chirho
                    .checked_add(event_chirho.amount_token_chirho)
                    .ok_or_else(|| anyhow!("realtime amount overflow"))?;
                clock_chirho.0 = event_chirho.at_ms_chirho;
                clock_chirho.1 = usage_chirho.billable_seconds_chirho;
                if usage_chirho.billable_seconds_chirho > open_chirho.max_seconds_chirho {
                    bail!(
                        "realtime session '{}' bills more seconds than authorized",
                        event_chirho.session_id_chirho
                    );
                }
            }
            RealtimeEventKindChirho::ProviderUsageChirho => {
                let usage_chirho = provider_usage_by_session_chirho
                    .entry(event_chirho.session_id_chirho.clone())
                    .or_default();
                usage_chirho.billable_seconds_chirho = usage_chirho
                    .billable_seconds_chirho
                    .checked_add(event_chirho.billable_seconds_chirho)
                    .ok_or_else(|| anyhow!("realtime provider usage seconds overflow"))?;
                usage_chirho.amount_token_chirho = usage_chirho
                    .amount_token_chirho
                    .checked_add(event_chirho.amount_token_chirho)
                    .ok_or_else(|| anyhow!("realtime provider usage amount overflow"))?;
                if usage_chirho.billable_seconds_chirho > open_chirho.max_seconds_chirho
                    || usage_chirho.amount_token_chirho > open_chirho.authorized_token_chirho
                {
                    bail!(
                        "realtime provider usage for '{}' exceeds authorized session budget",
                        event_chirho.session_id_chirho
                    );
                }
            }
            RealtimeEventKindChirho::UserSpokeChirho
            | RealtimeEventKindChirho::LlmRespondedChirho => {}
        }
    }
    for (session_id_chirho, records_chirho) in by_session_chirho {
        let opens_chirho: Vec<_> = records_chirho
            .iter()
            .filter(|record_chirho| {
                record_chirho.status_chirho == RealtimeSessionStatusChirho::OpenChirho
            })
            .copied()
            .collect();
        if opens_chirho.len() != 1 {
            bail!("realtime session '{session_id_chirho}' must have exactly one open record");
        }
        let open_chirho = opens_chirho[0];
        if let Some(view_chirho) = ledger_view_chirho {
            view_chirho.assert_entry_chirho(
                open_chirho.reserve_ledger_seq_chirho,
                &format!("realtime session reserve {session_id_chirho}"),
                &[
                    RealtimeLegacyPostingChirho {
                        account_chirho: open_chirho.payer_chirho.clone(),
                        amount_token_chirho: -open_chirho.authorized_token_chirho,
                    },
                    RealtimeLegacyPostingChirho {
                        account_chirho: open_chirho.reserve_account_chirho.clone(),
                        amount_token_chirho: open_chirho.authorized_token_chirho,
                    },
                ],
            )?;
        }
        let closes_chirho: Vec<_> = records_chirho
            .iter()
            .filter(|record_chirho| {
                record_chirho.status_chirho == RealtimeSessionStatusChirho::ClosedChirho
            })
            .copied()
            .collect();
        if closes_chirho.len() > 1 {
            bail!("realtime session '{session_id_chirho}' has multiple close records");
        }
        if let Some(close_chirho) = closes_chirho.first() {
            verify_close_record_chirho(
                root_chirho,
                ledger_view_chirho,
                &events_chirho,
                open_chirho,
                close_chirho,
            )?;
            if let Some(provider_usage_chirho) =
                provider_usage_by_session_chirho.get(&session_id_chirho)
            {
                if provider_usage_chirho.billable_seconds_chirho
                    != close_chirho.billed_seconds_chirho
                    || provider_usage_chirho.amount_token_chirho
                        != close_chirho.settled_token_chirho
                {
                    bail!(
                        "realtime provider usage for '{}' does not reconcile with settled session cost",
                        session_id_chirho
                    );
                }
            }
        }
    }
    Ok((sessions_chirho.len(), events_chirho.len()))
}

fn verify_close_record_chirho(
    root_chirho: &Path,
    ledger_view_chirho: Option<&dyn RealtimeLegacyLedgerViewChirho>,
    events_chirho: &[RealtimeEventRecordChirho],
    open_chirho: &RealtimeSessionRecordChirho,
    close_chirho: &RealtimeSessionRecordChirho,
) -> Result<()> {
    if close_chirho.session_id_chirho != open_chirho.session_id_chirho
        || close_chirho.reserve_ledger_seq_chirho != open_chirho.reserve_ledger_seq_chirho
        || close_chirho.authorized_token_chirho != open_chirho.authorized_token_chirho
    {
        bail!("closed realtime session conflicts with open record");
    }
    let expected_duration_chirho =
        elapsed_seconds_chirho(open_chirho.at_ms_chirho, close_chirho.at_ms_chirho)?;
    if close_chirho.duration_seconds_chirho != expected_duration_chirho {
        bail!("closed realtime session duration does not match signed timestamps");
    }
    let artifact_hash_chirho = close_chirho
        .transcript_chirho
        .as_ref()
        .ok_or_else(|| anyhow!("closed realtime session missing transcript"))?;
    let artifact_chirho: RealtimeTranscriptArtifactChirho =
        store_chirho::get_object_chirho(root_chirho, artifact_hash_chirho)?;
    if artifact_chirho.session_id_chirho != close_chirho.session_id_chirho
        || artifact_chirho.app_chirho != close_chirho.app_chirho
        || artifact_chirho.caller_chirho != close_chirho.caller_chirho
        || artifact_chirho.provider_account_chirho != close_chirho.provider_account_chirho
        || artifact_chirho.duration_seconds_chirho != close_chirho.duration_seconds_chirho
        || artifact_chirho.billed_seconds_chirho != close_chirho.billed_seconds_chirho
        || artifact_chirho.settled_token_chirho != close_chirho.settled_token_chirho
        || artifact_chirho.released_token_chirho != close_chirho.released_token_chirho
    {
        bail!("realtime transcript artifact does not match close record");
    }
    validate_realtime_private_blob_ref_subject_chirho(
        root_chirho,
        "realtime transcript artifact transcript_blob_chirho",
        &artifact_chirho.transcript_blob_chirho,
        &close_chirho.caller_chirho,
    )?;
    let expected_payloads_chirho: Vec<_> = events_chirho
        .iter()
        .filter(|event_chirho| event_chirho.session_id_chirho == close_chirho.session_id_chirho)
        .filter(|event_chirho| {
            event_chirho.kind_chirho != RealtimeEventKindChirho::ProviderUsageChirho
        })
        .map(|event_chirho| event_chirho.payload_chirho.clone())
        .collect();
    if artifact_chirho.event_payloads_chirho != expected_payloads_chirho {
        bail!("realtime transcript artifact event payloads do not match session events");
    }
    let prior_tick_token_chirho = realtime_usage_from_events_chirho(events_chirho)
        .get(&close_chirho.session_id_chirho)
        .map(|usage_chirho| usage_chirho.amount_token_chirho)
        .unwrap_or(0);
    let close_provider_token_chirho = close_chirho
        .settled_token_chirho
        .checked_sub(prior_tick_token_chirho)
        .ok_or_else(|| anyhow!("realtime close prior usage underflow"))?;
    let total_close_token_chirho = close_provider_token_chirho
        .checked_add(close_chirho.released_token_chirho)
        .ok_or_else(|| anyhow!("realtime close total overflow"))?;
    if total_close_token_chirho > 0 {
        let ledger_seq_chirho = close_chirho
            .settlement_ledger_seq_chirho
            .ok_or_else(|| anyhow!("closed realtime session missing settlement ledger seq"))?;
        let mut postings_chirho = vec![RealtimeLegacyPostingChirho {
            account_chirho: open_chirho.reserve_account_chirho.clone(),
            amount_token_chirho: -total_close_token_chirho,
        }];
        if close_provider_token_chirho > 0 {
            postings_chirho.push(RealtimeLegacyPostingChirho {
                account_chirho: open_chirho.provider_account_chirho.clone(),
                amount_token_chirho: close_provider_token_chirho,
            });
        }
        if close_chirho.released_token_chirho > 0 {
            postings_chirho.push(RealtimeLegacyPostingChirho {
                account_chirho: open_chirho.payer_chirho.clone(),
                amount_token_chirho: close_chirho.released_token_chirho,
            });
        }
        if let Some(view_chirho) = ledger_view_chirho {
            view_chirho.assert_entry_chirho(
                ledger_seq_chirho,
                &format!("realtime session close {}", close_chirho.session_id_chirho),
                &postings_chirho,
            )?;
        }
    }
    Ok(())
}

pub fn reveal_realtime_transcript_evidence_chirho(
    root_chirho: &Path,
    ledger_view_chirho: Option<&dyn RealtimeLegacyLedgerViewChirho>,
    session_id_chirho: &str,
    accessed_by_chirho: &str,
    purpose_chirho: &str,
) -> Result<RealtimeTranscriptRevealChirho> {
    validate_session_id_chirho(session_id_chirho)?;
    validate_nonempty_chirho("purpose_chirho", purpose_chirho)?;
    verify_realtime_evidence_chirho(root_chirho, ledger_view_chirho)?;
    let close_chirho = closed_session_record_chirho(root_chirho, session_id_chirho)?
        .ok_or_else(|| anyhow!("realtime session '{session_id_chirho}' is not closed"))?;
    let artifact_hash_chirho = close_chirho
        .transcript_chirho
        .clone()
        .ok_or_else(|| anyhow!("closed realtime session missing transcript artifact"))?;
    let artifact_chirho: RealtimeTranscriptArtifactChirho =
        store_chirho::get_object_chirho(root_chirho, &artifact_hash_chirho)?;
    if artifact_chirho.session_id_chirho != close_chirho.session_id_chirho
        || artifact_chirho.app_chirho != close_chirho.app_chirho
        || artifact_chirho.caller_chirho != close_chirho.caller_chirho
        || artifact_chirho.provider_account_chirho != close_chirho.provider_account_chirho
    {
        bail!("realtime transcript artifact does not match close record");
    }
    let transcript_subject_chirho = privacy_chirho::private_blob_key_subject_chirho(
        root_chirho,
        &artifact_chirho.transcript_blob_chirho.key_id_chirho,
    )?
    .ok_or_else(|| anyhow!("realtime transcript private blob key is unavailable"))?;
    if transcript_subject_chirho != close_chirho.caller_chirho {
        bail!("realtime transcript private blob subject does not match caller");
    }
    let plaintext_chirho = privacy_chirho::load_private_blob_chirho(
        root_chirho,
        &artifact_chirho.transcript_blob_chirho,
    )?;
    let access_record_chirho = privacy_chirho::append_privacy_access_record_chirho(
        root_chirho,
        &close_chirho.caller_chirho,
        accessed_by_chirho,
        &close_chirho.app_chirho,
        &realtime_transcript_row_key_chirho(session_id_chirho)?,
        purpose_chirho,
        &artifact_chirho.transcript_blob_chirho,
    )?;
    Ok(RealtimeTranscriptRevealChirho {
        session_id_chirho: close_chirho.session_id_chirho,
        artifact_chirho: artifact_hash_chirho,
        transcript_blob_chirho: artifact_chirho.transcript_blob_chirho,
        access_record_chirho,
        plaintext_chirho,
    })
}

pub fn realtime_epilogue_input_chirho(
    close_chirho: &RealtimeSessionRecordChirho,
    artifact_hash_chirho: &HashChirho,
    artifact_chirho: &RealtimeTranscriptArtifactChirho,
) -> RealtimeEpilogueInputChirho {
    RealtimeEpilogueInputChirho {
        session_id_chirho: close_chirho.session_id_chirho.clone(),
        app_chirho: close_chirho.app_chirho.clone(),
        caller_chirho: close_chirho.caller_chirho.clone(),
        provider_account_chirho: close_chirho.provider_account_chirho.clone(),
        artifact_chirho: artifact_hash_chirho.clone(),
        close_seq_chirho: close_chirho.seq_chirho,
        duration_seconds_chirho: close_chirho.duration_seconds_chirho,
        billed_seconds_chirho: close_chirho.billed_seconds_chirho,
        settled_token_chirho: close_chirho.settled_token_chirho,
        released_token_chirho: close_chirho.released_token_chirho,
        settlement_ledger_seq_chirho: close_chirho.settlement_ledger_seq_chirho,
        transcript_blob_chirho: artifact_chirho.transcript_blob_chirho.clone(),
        event_payloads_chirho: artifact_chirho.event_payloads_chirho.clone(),
    }
}

pub fn epilogue_message_chirho(record_chirho: &RealtimeEpilogueRecordChirho) -> Result<Vec<u8>> {
    let mut message_chirho = record_chirho.clone();
    message_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&message_chirho)?)
}

pub fn verify_realtime_epilogues_evidence_chirho(
    root_chirho: &Path,
    ledger_view_chirho: Option<&dyn RealtimeLegacyLedgerViewChirho>,
) -> Result<usize> {
    verify_realtime_evidence_chirho(root_chirho, ledger_view_chirho)?;
    let records_chirho = load_realtime_epilogues_chirho(root_chirho)?;
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    for (index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!("realtime epilogue seq gap at index {index_chirho}");
        }
        if record_chirho.node_runs_chirho.is_empty() {
            bail!("realtime epilogue record has no DAG node runs");
        }
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &epilogue_message_chirho(record_chirho)?,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "realtime epilogue record #{} signature invalid",
                record_chirho.seq_chirho
            );
        }
        let close_chirho =
            closed_session_record_chirho(root_chirho, &record_chirho.session_id_chirho)?
                .ok_or_else(|| anyhow!("realtime epilogue references an open/missing session"))?;
        if close_chirho.app_chirho != record_chirho.app_chirho
            || close_chirho.caller_chirho != record_chirho.caller_chirho
            || close_chirho.transcript_chirho.as_ref() != Some(&record_chirho.artifact_chirho)
        {
            bail!("realtime epilogue close record mismatch");
        }
        let artifact_chirho: RealtimeTranscriptArtifactChirho =
            store_chirho::get_object_chirho(root_chirho, &record_chirho.artifact_chirho)?;
        let expected_input_chirho = realtime_epilogue_input_chirho(
            &close_chirho,
            &record_chirho.artifact_chirho,
            &artifact_chirho,
        );
        let expected_input_bytes_chirho = serde_json::to_vec(&expected_input_chirho)?;
        if cas_chirho::hash_chirho(&expected_input_bytes_chirho) != record_chirho.input_hash_chirho
        {
            bail!("realtime epilogue input hash mismatch");
        }
        let stored_input_chirho =
            cas_chirho::get_chirho(root_chirho, &record_chirho.input_hash_chirho)
                .with_context(|| "realtime epilogue input payload missing from CAS")?;
        if stored_input_chirho != expected_input_bytes_chirho {
            bail!("realtime epilogue input payload mismatch");
        }
        let dag_chirho: DagChirho =
            store_chirho::get_object_chirho(root_chirho, &record_chirho.dag_chirho)?;
        ensure_pure_epilogue_dag_chirho(root_chirho, &dag_chirho)?;
        verify_epilogue_dag_run_chirho(
            root_chirho,
            &dag_chirho,
            &record_chirho.input_hash_chirho,
            record_chirho,
        )?;
    }
    Ok(records_chirho.len())
}

pub fn ensure_pure_epilogue_dag_chirho(root_chirho: &Path, dag_chirho: &DagChirho) -> Result<()> {
    if dag_chirho.nodes_chirho.is_empty() {
        bail!("realtime epilogue DAG must contain at least one node");
    }
    for node_hash_chirho in &dag_chirho.nodes_chirho {
        let node_chirho: NodeDefChirho =
            store_chirho::get_object_chirho(root_chirho, node_hash_chirho)?;
        if !node_chirho.capabilities_chirho.is_empty() {
            bail!(
                "realtime epilogue DAG node '{}' must be pure; effects belong outside verification replay",
                node_chirho.name_chirho
            );
        }
    }
    Ok(())
}

fn verify_epilogue_dag_run_chirho(
    root_chirho: &Path,
    dag_chirho: &DagChirho,
    input_hash_chirho: &HashChirho,
    record_chirho: &RealtimeEpilogueRecordChirho,
) -> Result<()> {
    let mut outputs_chirho: BTreeMap<(HashChirho, String), HashChirho> = BTreeMap::new();
    let mut run_of_chirho: BTreeMap<HashChirho, HashChirho> = BTreeMap::new();
    let mut seen_nodes_chirho = BTreeSet::new();
    for node_run_chirho in &record_chirho.node_runs_chirho {
        if !dag_chirho
            .nodes_chirho
            .contains(&node_run_chirho.node_chirho)
        {
            bail!("realtime epilogue record references node outside DAG");
        }
        if !seen_nodes_chirho.insert(node_run_chirho.node_chirho.clone()) {
            bail!("realtime epilogue record repeats a DAG node");
        }
        let node_def_chirho: NodeDefChirho =
            store_chirho::get_object_chirho(root_chirho, &node_run_chirho.node_chirho)?;
        if node_def_chirho.name_chirho != node_run_chirho.node_name_chirho {
            bail!("realtime epilogue node name mismatch");
        }
        if !node_def_chirho.capabilities_chirho.is_empty() {
            bail!("realtime epilogue DAG run contains an effect node");
        }
        let incoming_chirho: Vec<&EdgeChirho> = dag_chirho
            .edges_chirho
            .iter()
            .filter(|edge_chirho| edge_chirho.to_node_chirho == node_run_chirho.node_chirho)
            .collect();
        if incoming_chirho.len() > 1 {
            bail!("realtime epilogue verifier supports one input per DAG node");
        }
        let (expected_input_chirho, expected_parents_chirho) = if let Some(edge_chirho) =
            incoming_chirho.first()
        {
            let upstream_output_chirho = outputs_chirho
                .get(&(
                    edge_chirho.from_node_chirho.clone(),
                    edge_chirho.from_port_chirho.clone(),
                ))
                .ok_or_else(|| anyhow!("realtime epilogue DAG node ran before its parent"))?
                .clone();
            let parent_run_chirho = run_of_chirho
                .get(&edge_chirho.from_node_chirho)
                .cloned()
                .ok_or_else(|| anyhow!("realtime epilogue parent run missing"))?;
            (upstream_output_chirho, vec![parent_run_chirho])
        } else {
            (
                input_hash_chirho.clone(),
                vec![record_chirho.artifact_chirho.clone()],
            )
        };
        let input_port_chirho = node_def_chirho
            .inputs_chirho
            .first()
            .map(|port_chirho| port_chirho.name_chirho.clone())
            .unwrap_or_else(|| "in".to_string());
        let caps_hash_chirho =
            store_chirho::hash_object_chirho(&node_def_chirho.capabilities_chirho)?;
        let expected_run_chirho = store_chirho::hash_object_chirho(&RunKeyChirho {
            node_chirho: node_run_chirho.node_chirho.clone(),
            inputs_chirho: BTreeMap::from([(input_port_chirho, expected_input_chirho)]),
            caps_chirho: caps_hash_chirho,
        })?;
        if expected_run_chirho != node_run_chirho.run_chirho {
            bail!("realtime epilogue run key mismatch");
        }
        let result_chirho =
            cache_chirho::load_sealed_result_chirho(root_chirho, &node_run_chirho.run_chirho)?
                .ok_or_else(|| anyhow!("realtime epilogue run result missing"))?;
        if result_chirho.run_chirho != node_run_chirho.run_chirho {
            bail!("realtime epilogue run result identity mismatch");
        }
        if result_chirho.parents_chirho != expected_parents_chirho {
            bail!("realtime epilogue provenance parents mismatch");
        }
        if result_chirho.status_chirho != RunStatusChirho::OkChirho
            || !result_chirho.effects_chirho.is_empty()
        {
            bail!("realtime epilogue run must be pure and successful");
        }
        for (port_chirho, hash_chirho) in &result_chirho.outputs_chirho {
            outputs_chirho.insert(
                (node_run_chirho.node_chirho.clone(), port_chirho.clone()),
                hash_chirho.clone(),
            );
        }
        run_of_chirho.insert(
            node_run_chirho.node_chirho.clone(),
            node_run_chirho.run_chirho.clone(),
        );
    }
    if seen_nodes_chirho.len() != dag_chirho.nodes_chirho.len() {
        bail!("realtime epilogue record did not run every DAG node");
    }
    let sink_chirho = epilogue_sink_node_chirho(dag_chirho)?;
    let sink_run_chirho = run_of_chirho
        .get(&sink_chirho)
        .ok_or_else(|| anyhow!("realtime epilogue sink run missing"))?;
    if sink_run_chirho != &record_chirho.sink_run_chirho {
        bail!("realtime epilogue sink run mismatch");
    }
    let sink_def_chirho: NodeDefChirho =
        store_chirho::get_object_chirho(root_chirho, &sink_chirho)?;
    let sink_port_chirho = sink_def_chirho
        .outputs_chirho
        .first()
        .map(|port_chirho| port_chirho.name_chirho.clone())
        .unwrap_or_else(|| "out".to_string());
    let payload_hash_chirho = outputs_chirho
        .get(&(sink_chirho, sink_port_chirho))
        .ok_or_else(|| anyhow!("realtime epilogue sink output missing"))?;
    if payload_hash_chirho != &record_chirho.payload_hash_chirho {
        bail!("realtime epilogue payload hash mismatch");
    }
    cas_chirho::get_chirho(root_chirho, &record_chirho.payload_hash_chirho)
        .with_context(|| "realtime epilogue payload missing from CAS")?;
    verify_chirho::verify_chirho(root_chirho, &record_chirho.sink_run_chirho)?;
    Ok(())
}

fn epilogue_sink_node_chirho(dag_chirho: &DagChirho) -> Result<HashChirho> {
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
        0 => bail!("realtime epilogue DAG has no sink"),
        n_chirho => bail!("realtime epilogue DAG has {n_chirho} sinks"),
    }
}
