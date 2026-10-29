// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Restart-readable R2/R3 progress for one exact GD7 losing-effect obligation.
//!
//! This sibling references the 5a durable receipt and re-derivation contract but cannot construct
//! the affine `MintedGd7LosingEffectObligationChirho`. Provider calls, journal appends, current
//! winner authority, and sink fencing remain typed seams for the later R4 composition.

#![allow(
    dead_code,
    reason = "R4 composition is intentionally deferred; this standalone R2/R3 brick exposes its bounded API before wiring"
)]

use super::super::contract_chirho::is_lower_hex_digest_chirho;
use crate::reconciliation_chirho::Gd7ReconciliationVerifierPortChirho;
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::cell::Cell;
use std::error::Error;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

const GD7_RECONCILIATION_NAMESPACE_CHIRHO: &str = "gd7-reconciliation-chirho";
pub(crate) const GD7_OBLIGATION_PROCESSING_SCHEMA_V1_CHIRHO: &str =
    "gd7-obligation-processing-v1-chirho";
pub(crate) const GD7_OBLIGATION_PROCESSING_SCHEMA_V2_CHIRHO: &str =
    "gd7-obligation-processing-v2-chirho";
const MAX_GD7_OBLIGATION_PROCESSING_BYTES_CHIRHO: usize = 64 * 1024;
const MAX_GD7_OBLIGATION_PROCESSING_REFERENCE_BYTES_CHIRHO: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Gd7ObligationTerminalProgressChirho {
    AwaitingProviderChirho,
    ProviderIntentPersistedChirho,
    ProviderObservedChirho,
    JournalRecordedChirho,
    CompletedChirho,
    HeldManualChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gd7HeldManualClassificationChirho {
    HeldManualOpenChirho,
    HeldManualDisposedChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7HeldManualDispositionChirho {
    mint_identity_digest_chirho: String,
    operator_key_id_chirho: String,
    disposed_at_unix_seconds_chirho: u64,
    compensating_effect_ref_chirho: Option<String>,
    no_action_reason_chirho: Option<String>,
    sig_chirho: String,
}

impl Gd7HeldManualDispositionChirho {
    pub(crate) fn new_chirho(
        mint_identity_digest_chirho: String,
        operator_key_id_chirho: String,
        disposed_at_unix_seconds_chirho: u64,
        compensating_effect_ref_chirho: Option<String>,
        no_action_reason_chirho: Option<String>,
        sig_chirho: String,
    ) -> Self {
        Self {
            mint_identity_digest_chirho,
            operator_key_id_chirho,
            disposed_at_unix_seconds_chirho,
            compensating_effect_ref_chirho,
            no_action_reason_chirho,
            sig_chirho,
        }
    }

    pub(crate) fn operator_key_id_chirho(&self) -> &str {
        &self.operator_key_id_chirho
    }

    pub(crate) fn with_signature_chirho(mut self, sig_chirho: String) -> Self {
        self.sig_chirho = sig_chirho;
        self
    }

    pub(crate) fn canonical_unsigned_bytes_chirho(
        &self,
    ) -> Result<Vec<u8>, Gd7ObligationProcessingRefusalChirho> {
        let mut unsigned_chirho = self.clone();
        unsigned_chirho.sig_chirho.clear();
        serde_json::to_vec(&unsigned_chirho)
            .map_err(|_| Gd7ObligationProcessingRefusalChirho::SerializationChirho)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Gd7ProviderObservationSlotChirho {
    observation_ref_chirho: String,
    provider_effect_id_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Gd7ProviderIntentSlotChirho {
    provider_idempotency_key_chirho: String,
    bounded_payload_digest_chirho: String,
    persisted_at_unix_seconds_chirho: u64,
    resume_attempts_chirho: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Gd7JournalReceiptSlotChirho {
    receipt_ref_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7ObligationProcessingStateChirho {
    schema_chirho: String,
    mint_identity_digest_chirho: String,
    obligation_receipt_ref_chirho: String,
    canonical_obligation_digest_chirho: String,
    inverse_authority_ref_chirho: String,
    action_idempotency_key_chirho: String,
    provider_intent_chirho: Option<Gd7ProviderIntentSlotChirho>,
    provider_observation_chirho: Option<Gd7ProviderObservationSlotChirho>,
    journal_receipt_chirho: Option<Gd7JournalReceiptSlotChirho>,
    terminal_progress_chirho: Gd7ObligationTerminalProgressChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    held_manual_disposition_chirho: Option<Gd7HeldManualDispositionChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gd7ObligationProcessingDisplayRecordChirho {
    pub path_chirho: String,
    pub valid_chirho: bool,
    pub state_chirho: Option<Gd7ObligationProcessingStateChirho>,
    pub validation_error_chirho: Option<String>,
}

#[allow(
    dead_code,
    reason = "R4 composition consumes these bounded accessors after this standalone R2/R3 brick"
)]
impl Gd7ObligationProcessingStateChirho {
    pub(crate) fn mint_identity_digest_chirho(&self) -> &str {
        &self.mint_identity_digest_chirho
    }

    pub(crate) fn obligation_receipt_ref_chirho(&self) -> &str {
        &self.obligation_receipt_ref_chirho
    }

    pub(crate) fn canonical_obligation_digest_chirho(&self) -> &str {
        &self.canonical_obligation_digest_chirho
    }

    pub(crate) fn inverse_authority_ref_chirho(&self) -> &str {
        &self.inverse_authority_ref_chirho
    }

    pub(crate) fn action_idempotency_key_chirho(&self) -> &str {
        &self.action_idempotency_key_chirho
    }

    /// `pub` alongside `terminal_progress_chirho` and for the same consumer: the capstone arm in
    /// `cairn-ledger-regenesis-chirho` receives this state from the `pub` wire methods and must
    /// assert WHICH observation was recorded, not merely that some state came back. Read-only —
    /// nothing outside the crate can write an observation or a receipt.
    pub fn provider_observation_ref_chirho(&self) -> Option<&str> {
        self.provider_observation_chirho
            .as_ref()
            .map(|slot_chirho| slot_chirho.observation_ref_chirho.as_str())
    }

    pub(crate) fn provider_effect_id_chirho(&self) -> Option<&str> {
        self.provider_observation_chirho
            .as_ref()
            .map(|slot_chirho| slot_chirho.provider_effect_id_chirho.as_str())
    }

    pub(crate) fn provider_idempotency_key_chirho(&self) -> Option<&str> {
        self.provider_intent_chirho
            .as_ref()
            .map(|slot_chirho| slot_chirho.provider_idempotency_key_chirho.as_str())
    }

    pub(crate) fn provider_payload_digest_chirho(&self) -> Option<&str> {
        self.provider_intent_chirho
            .as_ref()
            .map(|slot_chirho| slot_chirho.bounded_payload_digest_chirho.as_str())
    }

    pub(crate) fn provider_intent_persisted_at_unix_seconds_chirho(&self) -> Option<u64> {
        self.provider_intent_chirho
            .as_ref()
            .map(|slot_chirho| slot_chirho.persisted_at_unix_seconds_chirho)
    }

    pub(crate) fn provider_resume_attempts_chirho(&self) -> Option<u8> {
        self.provider_intent_chirho
            .as_ref()
            .map(|slot_chirho| slot_chirho.resume_attempts_chirho)
    }

    /// `pub` for the same reason as `provider_observation_ref_chirho` directly above: the capstone
    /// arm must assert the completed obligation carries the fenced append's own record digest, and
    /// that replay returns the SAME receipt. Read-only.
    pub fn journal_receipt_ref_chirho(&self) -> Option<&str> {
        self.journal_receipt_chirho
            .as_ref()
            .map(|slot_chirho| slot_chirho.receipt_ref_chirho.as_str())
    }

    pub fn terminal_progress_chirho(&self) -> Gd7ObligationTerminalProgressChirho {
        self.terminal_progress_chirho
    }

    pub fn held_manual_disposition_chirho(&self) -> Option<&Gd7HeldManualDispositionChirho> {
        self.held_manual_disposition_chirho.as_ref()
    }

    pub fn held_manual_classification_chirho(&self) -> Option<Gd7HeldManualClassificationChirho> {
        if self.terminal_progress_chirho != Gd7ObligationTerminalProgressChirho::HeldManualChirho {
            return None;
        }
        Some(if self.held_manual_disposition_chirho.is_some() {
            Gd7HeldManualClassificationChirho::HeldManualDisposedChirho
        } else {
            Gd7HeldManualClassificationChirho::HeldManualOpenChirho
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gd7ObligationProcessingRefusalChirho {
    InvalidReferenceChirho,
    InvalidStateChirho,
    StateCollisionChirho,
    MissingStateChirho,
    OversizedStateChirho,
    StorageChirho,
    SerializationChirho,
    ResumeWindowExpiredChirho,
    ResumeAttemptsExceededChirho,
    PayloadCollisionChirho,
    #[cfg(test)]
    CrashInjectedChirho,
}

impl fmt::Display for Gd7ObligationProcessingRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message_chirho = match self {
            Self::InvalidReferenceChirho => "GD7 obligation processing reference is invalid",
            Self::InvalidStateChirho => "GD7 obligation processing state is invalid",
            Self::StateCollisionChirho => "GD7 obligation action or obligation identity collides",
            Self::MissingStateChirho => "GD7 obligation processing state is missing",
            Self::OversizedStateChirho => "GD7 obligation processing state exceeds its bound",
            Self::StorageChirho => "GD7 obligation processing storage refused",
            Self::SerializationChirho => "GD7 obligation processing state could not serialize",
            Self::ResumeWindowExpiredChirho => "GD7 provider resume window is unavailable",
            Self::ResumeAttemptsExceededChirho => "GD7 provider resume attempt bound exceeded",
            Self::PayloadCollisionChirho => "GD7 provider payload identity collides",
            #[cfg(test)]
            Self::CrashInjectedChirho => "GD7 obligation processing test crash injected",
        };
        formatter_chirho.write_str(message_chirho)
    }
}

impl Error for Gd7ObligationProcessingRefusalChirho {}

pub(crate) fn gd7_obligation_processing_state_path_chirho(
    mint_identity_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7ObligationProcessingRefusalChirho> {
    if !is_lower_hex_digest_chirho(mint_identity_digest_chirho) {
        return Err(Gd7ObligationProcessingRefusalChirho::InvalidReferenceChirho);
    }
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/obligation-processing-chirho/{}/{}/{mint_identity_digest_chirho}.json",
        &mint_identity_digest_chirho[..2],
        &mint_identity_digest_chirho[2..4],
    )))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn create_or_load_gd7_obligation_processing_state_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    mint_identity_digest_chirho: &str,
    obligation_receipt_ref_chirho: &str,
    canonical_obligation_digest_chirho: &str,
    inverse_authority_ref_chirho: &str,
    action_idempotency_key_chirho: &str,
) -> Result<Gd7ObligationProcessingStateChirho, Gd7ObligationProcessingRefusalChirho> {
    validate_state_inputs_chirho(
        mint_identity_digest_chirho,
        obligation_receipt_ref_chirho,
        canonical_obligation_digest_chirho,
        inverse_authority_ref_chirho,
        action_idempotency_key_chirho,
    )?;
    let state_chirho = Gd7ObligationProcessingStateChirho {
        schema_chirho: GD7_OBLIGATION_PROCESSING_SCHEMA_V2_CHIRHO.to_owned(),
        mint_identity_digest_chirho: mint_identity_digest_chirho.to_owned(),
        obligation_receipt_ref_chirho: obligation_receipt_ref_chirho.to_owned(),
        canonical_obligation_digest_chirho: canonical_obligation_digest_chirho.to_owned(),
        inverse_authority_ref_chirho: inverse_authority_ref_chirho.to_owned(),
        action_idempotency_key_chirho: action_idempotency_key_chirho.to_owned(),
        provider_intent_chirho: None,
        provider_observation_chirho: None,
        journal_receipt_chirho: None,
        terminal_progress_chirho: Gd7ObligationTerminalProgressChirho::AwaitingProviderChirho,
        held_manual_disposition_chirho: None,
    };
    let path_chirho = gd7_obligation_processing_state_path_chirho(mint_identity_digest_chirho)?;
    let bytes_chirho = serialize_state_chirho(&state_chirho)?;
    match storage_chirho
        .create_durable_chirho(&path_chirho, &bytes_chirho)
        .map_err(|_| Gd7ObligationProcessingRefusalChirho::StorageChirho)?
    {
        CreateDurableOutcomeChirho::CreatedChirho => Ok(state_chirho),
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_chirho = load_gd7_obligation_processing_state_chirho(
                storage_chirho,
                mint_identity_digest_chirho,
            )?;
            if existing_chirho.obligation_receipt_ref_chirho != obligation_receipt_ref_chirho
                || existing_chirho.canonical_obligation_digest_chirho
                    != canonical_obligation_digest_chirho
                || existing_chirho.inverse_authority_ref_chirho != inverse_authority_ref_chirho
                || existing_chirho.action_idempotency_key_chirho != action_idempotency_key_chirho
            {
                return Err(Gd7ObligationProcessingRefusalChirho::StateCollisionChirho);
            }
            Ok(existing_chirho)
        }
    }
}

pub fn load_gd7_obligation_processing_state_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    mint_identity_digest_chirho: &str,
) -> Result<Gd7ObligationProcessingStateChirho, Gd7ObligationProcessingRefusalChirho> {
    let path_chirho = gd7_obligation_processing_state_path_chirho(mint_identity_digest_chirho)?;
    let bytes_chirho = storage_chirho
        .read_all_chirho(&path_chirho)
        .map_err(|_| Gd7ObligationProcessingRefusalChirho::StorageChirho)?
        .ok_or(Gd7ObligationProcessingRefusalChirho::MissingStateChirho)?;
    deserialize_state_chirho(&bytes_chirho)
}

pub fn load_gd7_obligation_processing_for_display_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
) -> Result<Vec<Gd7ObligationProcessingDisplayRecordChirho>, Gd7ObligationProcessingRefusalChirho> {
    let prefix_chirho = StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/obligation-processing-chirho/"
    ));
    let paths_chirho = storage_chirho
        .list_chirho(&prefix_chirho)
        .map_err(|_| Gd7ObligationProcessingRefusalChirho::StorageChirho)?;
    let mut records_chirho = Vec::with_capacity(paths_chirho.len());
    for path_chirho in paths_chirho {
        let state_result_chirho = storage_chirho
            .read_all_chirho(&path_chirho)
            .map_err(|_| Gd7ObligationProcessingRefusalChirho::StorageChirho)?
            .ok_or(Gd7ObligationProcessingRefusalChirho::MissingStateChirho)
            .and_then(|bytes_chirho| deserialize_state_chirho(&bytes_chirho));
        match state_result_chirho {
            Ok(state_chirho) => records_chirho.push(Gd7ObligationProcessingDisplayRecordChirho {
                path_chirho: path_chirho.key_chirho().to_owned(),
                valid_chirho: true,
                state_chirho: Some(state_chirho),
                validation_error_chirho: None,
            }),
            Err(error_chirho) => records_chirho.push(Gd7ObligationProcessingDisplayRecordChirho {
                path_chirho: path_chirho.key_chirho().to_owned(),
                valid_chirho: false,
                state_chirho: None,
                validation_error_chirho: Some(error_chirho.to_string()),
            }),
        }
    }
    Ok(records_chirho)
}

pub(crate) fn record_gd7_provider_observation_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    state_chirho: &Gd7ObligationProcessingStateChirho,
    observation_ref_chirho: &str,
    provider_effect_id_chirho: &str,
) -> Result<Gd7ObligationProcessingStateChirho, Gd7ObligationProcessingRefusalChirho> {
    validate_reference_chirho(observation_ref_chirho)?;
    validate_reference_chirho(provider_effect_id_chirho)?;
    let mut next_state_chirho = state_chirho.clone();
    match next_state_chirho.terminal_progress_chirho {
        Gd7ObligationTerminalProgressChirho::ProviderIntentPersistedChirho => {}
        Gd7ObligationTerminalProgressChirho::AwaitingProviderChirho => {
            return Err(Gd7ObligationProcessingRefusalChirho::InvalidStateChirho)
        }
        Gd7ObligationTerminalProgressChirho::ProviderObservedChirho
        | Gd7ObligationTerminalProgressChirho::JournalRecordedChirho
        | Gd7ObligationTerminalProgressChirho::CompletedChirho => {
            if next_state_chirho.provider_observation_ref_chirho() != Some(observation_ref_chirho) {
                return Err(Gd7ObligationProcessingRefusalChirho::StateCollisionChirho);
            }
            if next_state_chirho.provider_effect_id_chirho() != Some(provider_effect_id_chirho) {
                return Err(Gd7ObligationProcessingRefusalChirho::StateCollisionChirho);
            }
            return Ok(next_state_chirho);
        }
        Gd7ObligationTerminalProgressChirho::HeldManualChirho => {
            return Err(Gd7ObligationProcessingRefusalChirho::InvalidStateChirho)
        }
    }
    next_state_chirho.provider_observation_chirho = Some(Gd7ProviderObservationSlotChirho {
        observation_ref_chirho: observation_ref_chirho.to_owned(),
        provider_effect_id_chirho: provider_effect_id_chirho.to_owned(),
    });
    next_state_chirho.terminal_progress_chirho =
        Gd7ObligationTerminalProgressChirho::ProviderObservedChirho;
    failpoint_before_durable_transition_chirho()?;
    persist_state_chirho(storage_chirho, &next_state_chirho)
}

pub(crate) fn record_gd7_provider_intent_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    state_chirho: &Gd7ObligationProcessingStateChirho,
    provider_idempotency_key_chirho: &str,
    bounded_payload_digest_chirho: &str,
) -> Result<Gd7ObligationProcessingStateChirho, Gd7ObligationProcessingRefusalChirho> {
    validate_reference_chirho(provider_idempotency_key_chirho)?;
    if !is_lower_hex_digest_chirho(bounded_payload_digest_chirho) {
        return Err(Gd7ObligationProcessingRefusalChirho::InvalidReferenceChirho);
    }
    let mut next_state_chirho = state_chirho.clone();
    if let Some(existing_chirho) = next_state_chirho.provider_idempotency_key_chirho() {
        if existing_chirho != provider_idempotency_key_chirho {
            return Err(Gd7ObligationProcessingRefusalChirho::StateCollisionChirho);
        }
        return Ok(next_state_chirho);
    }
    if next_state_chirho.terminal_progress_chirho
        != Gd7ObligationTerminalProgressChirho::AwaitingProviderChirho
    {
        return Err(Gd7ObligationProcessingRefusalChirho::InvalidStateChirho);
    }
    let persisted_at_unix_seconds_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Gd7ObligationProcessingRefusalChirho::InvalidStateChirho)?
        .as_secs();
    next_state_chirho.provider_intent_chirho = Some(Gd7ProviderIntentSlotChirho {
        provider_idempotency_key_chirho: provider_idempotency_key_chirho.to_owned(),
        bounded_payload_digest_chirho: bounded_payload_digest_chirho.to_owned(),
        persisted_at_unix_seconds_chirho,
        resume_attempts_chirho: 0,
    });
    next_state_chirho.terminal_progress_chirho =
        Gd7ObligationTerminalProgressChirho::ProviderIntentPersistedChirho;
    failpoint_before_durable_transition_chirho()?;
    persist_state_chirho(storage_chirho, &next_state_chirho)
}

pub(crate) fn prepare_gd7_provider_resume_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    state_chirho: &Gd7ObligationProcessingStateChirho,
    bounded_payload_digest_chirho: &str,
    retention_seconds_chirho: u64,
    max_attempts_chirho: u8,
) -> Result<Gd7ObligationProcessingStateChirho, Gd7ObligationProcessingRefusalChirho> {
    let mut next_state_chirho = state_chirho.clone();
    let intent_chirho = next_state_chirho
        .provider_intent_chirho
        .as_mut()
        .ok_or(Gd7ObligationProcessingRefusalChirho::InvalidStateChirho)?;
    if next_state_chirho.terminal_progress_chirho
        != Gd7ObligationTerminalProgressChirho::ProviderIntentPersistedChirho
    {
        return Err(Gd7ObligationProcessingRefusalChirho::InvalidStateChirho);
    }
    if intent_chirho.bounded_payload_digest_chirho != bounded_payload_digest_chirho {
        return Err(Gd7ObligationProcessingRefusalChirho::PayloadCollisionChirho);
    }
    let now_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Gd7ObligationProcessingRefusalChirho::ResumeWindowExpiredChirho)?
        .as_secs();
    if now_chirho < intent_chirho.persisted_at_unix_seconds_chirho {
        return Err(Gd7ObligationProcessingRefusalChirho::ResumeWindowExpiredChirho);
    }
    let elapsed_chirho = now_chirho - intent_chirho.persisted_at_unix_seconds_chirho;
    if elapsed_chirho >= retention_seconds_chirho {
        return Err(Gd7ObligationProcessingRefusalChirho::ResumeWindowExpiredChirho);
    }
    if intent_chirho.resume_attempts_chirho >= max_attempts_chirho {
        return Err(Gd7ObligationProcessingRefusalChirho::ResumeAttemptsExceededChirho);
    }
    intent_chirho.resume_attempts_chirho = intent_chirho.resume_attempts_chirho.saturating_add(1);
    failpoint_before_durable_transition_chirho()?;
    persist_state_chirho(storage_chirho, &next_state_chirho)
}

pub(crate) fn record_gd7_journal_receipt_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    state_chirho: &Gd7ObligationProcessingStateChirho,
    receipt_ref_chirho: &str,
) -> Result<Gd7ObligationProcessingStateChirho, Gd7ObligationProcessingRefusalChirho> {
    validate_reference_chirho(receipt_ref_chirho)?;
    if state_chirho.provider_observation_chirho.is_none() {
        return Err(Gd7ObligationProcessingRefusalChirho::InvalidStateChirho);
    }
    let mut next_state_chirho = state_chirho.clone();
    match next_state_chirho.terminal_progress_chirho {
        Gd7ObligationTerminalProgressChirho::JournalRecordedChirho
        | Gd7ObligationTerminalProgressChirho::CompletedChirho => {
            if next_state_chirho.journal_receipt_ref_chirho() != Some(receipt_ref_chirho) {
                return Err(Gd7ObligationProcessingRefusalChirho::StateCollisionChirho);
            }
            return Ok(next_state_chirho);
        }
        Gd7ObligationTerminalProgressChirho::ProviderObservedChirho => {}
        Gd7ObligationTerminalProgressChirho::ProviderIntentPersistedChirho => {
            return Err(Gd7ObligationProcessingRefusalChirho::InvalidStateChirho)
        }
        Gd7ObligationTerminalProgressChirho::AwaitingProviderChirho => {
            return Err(Gd7ObligationProcessingRefusalChirho::InvalidStateChirho)
        }
        Gd7ObligationTerminalProgressChirho::HeldManualChirho => {
            return Err(Gd7ObligationProcessingRefusalChirho::InvalidStateChirho)
        }
    }
    next_state_chirho.journal_receipt_chirho = Some(Gd7JournalReceiptSlotChirho {
        receipt_ref_chirho: receipt_ref_chirho.to_owned(),
    });
    next_state_chirho.terminal_progress_chirho =
        Gd7ObligationTerminalProgressChirho::JournalRecordedChirho;
    failpoint_before_durable_transition_chirho()?;
    persist_state_chirho(storage_chirho, &next_state_chirho)
}

pub(crate) fn mark_gd7_obligation_completed_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    state_chirho: &Gd7ObligationProcessingStateChirho,
) -> Result<Gd7ObligationProcessingStateChirho, Gd7ObligationProcessingRefusalChirho> {
    if state_chirho.journal_receipt_chirho.is_none() {
        return Err(Gd7ObligationProcessingRefusalChirho::InvalidStateChirho);
    }
    if state_chirho.terminal_progress_chirho == Gd7ObligationTerminalProgressChirho::CompletedChirho
    {
        return Ok(state_chirho.clone());
    }
    if state_chirho.terminal_progress_chirho
        != Gd7ObligationTerminalProgressChirho::JournalRecordedChirho
    {
        return Err(Gd7ObligationProcessingRefusalChirho::InvalidStateChirho);
    }
    let mut next_state_chirho = state_chirho.clone();
    next_state_chirho.terminal_progress_chirho =
        Gd7ObligationTerminalProgressChirho::CompletedChirho;
    failpoint_before_durable_transition_chirho()?;
    persist_state_chirho(storage_chirho, &next_state_chirho)
}

pub(crate) fn mark_gd7_obligation_held_manual_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    state_chirho: &Gd7ObligationProcessingStateChirho,
) -> Result<Gd7ObligationProcessingStateChirho, Gd7ObligationProcessingRefusalChirho> {
    if state_chirho.terminal_progress_chirho == Gd7ObligationTerminalProgressChirho::CompletedChirho
    {
        return Err(Gd7ObligationProcessingRefusalChirho::InvalidStateChirho);
    }
    if state_chirho.terminal_progress_chirho
        == Gd7ObligationTerminalProgressChirho::HeldManualChirho
    {
        return Ok(state_chirho.clone());
    }
    let mut next_state_chirho = state_chirho.clone();
    next_state_chirho.terminal_progress_chirho =
        Gd7ObligationTerminalProgressChirho::HeldManualChirho;
    failpoint_before_durable_transition_chirho()?;
    persist_state_chirho(storage_chirho, &next_state_chirho)
}

pub fn dispose_gd7_obligation_held_manual_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    state_chirho: &Gd7ObligationProcessingStateChirho,
    disposition_chirho: Gd7HeldManualDispositionChirho,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<Gd7ObligationProcessingStateChirho, Gd7ObligationProcessingRefusalChirho> {
    if state_chirho.terminal_progress_chirho
        != Gd7ObligationTerminalProgressChirho::HeldManualChirho
    {
        return Err(Gd7ObligationProcessingRefusalChirho::InvalidStateChirho);
    }
    if state_chirho.held_manual_disposition_chirho.is_some() {
        return Err(Gd7ObligationProcessingRefusalChirho::StateCollisionChirho);
    }
    verify_held_manual_disposition_chirho(
        &disposition_chirho,
        state_chirho.mint_identity_digest_chirho(),
        verifier_chirho,
    )?;
    let mut next_state_chirho = state_chirho.clone();
    next_state_chirho.held_manual_disposition_chirho = Some(disposition_chirho);
    persist_state_chirho(storage_chirho, &next_state_chirho)
}

fn verify_held_manual_disposition_chirho(
    disposition_chirho: &Gd7HeldManualDispositionChirho,
    expected_mint_identity_digest_chirho: &str,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<(), Gd7ObligationProcessingRefusalChirho> {
    if disposition_chirho.mint_identity_digest_chirho != expected_mint_identity_digest_chirho
        || disposition_chirho.operator_key_id_chirho != verifier_chirho.key_id_chirho()
        || disposition_chirho.compensating_effect_ref_chirho.is_some()
            == disposition_chirho.no_action_reason_chirho.is_some()
    {
        return Err(Gd7ObligationProcessingRefusalChirho::InvalidStateChirho);
    }
    let mut unsigned_chirho = disposition_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    let bytes_chirho = serde_json::to_vec(&unsigned_chirho)
        .map_err(|_| Gd7ObligationProcessingRefusalChirho::SerializationChirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&bytes_chirho)
        .map_err(|_| Gd7ObligationProcessingRefusalChirho::SerializationChirho)?;
    if !verifier_chirho.verify_chirho(unsigned_line_chirho, &disposition_chirho.sig_chirho) {
        return Err(Gd7ObligationProcessingRefusalChirho::InvalidStateChirho);
    }
    Ok(())
}

#[cfg(test)]
std::thread_local! {
    static GD7_OBLIGATION_PROCESSING_FAILPOINT_CHIRHO: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
fn arm_next_durable_transition_failpoint_chirho() {
    GD7_OBLIGATION_PROCESSING_FAILPOINT_CHIRHO.with(|failpoint_chirho| {
        failpoint_chirho.set(true);
    });
}

fn failpoint_before_durable_transition_chirho() -> Result<(), Gd7ObligationProcessingRefusalChirho>
{
    #[cfg(test)]
    if GD7_OBLIGATION_PROCESSING_FAILPOINT_CHIRHO.with(|failpoint_chirho| {
        let armed_chirho = failpoint_chirho.get();
        failpoint_chirho.set(false);
        armed_chirho
    }) {
        return Err(Gd7ObligationProcessingRefusalChirho::CrashInjectedChirho);
    }
    Ok(())
}

fn persist_state_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    state_chirho: &Gd7ObligationProcessingStateChirho,
) -> Result<Gd7ObligationProcessingStateChirho, Gd7ObligationProcessingRefusalChirho> {
    let path_chirho =
        gd7_obligation_processing_state_path_chirho(&state_chirho.mint_identity_digest_chirho)?;
    let bytes_chirho = serialize_state_chirho(state_chirho)?;
    storage_chirho
        .atomic_write_chirho(&path_chirho, &bytes_chirho)
        .map_err(|_| Gd7ObligationProcessingRefusalChirho::StorageChirho)?;
    Ok(state_chirho.clone())
}

fn serialize_state_chirho(
    state_chirho: &Gd7ObligationProcessingStateChirho,
) -> Result<Vec<u8>, Gd7ObligationProcessingRefusalChirho> {
    let bytes_chirho = serde_json::to_vec(state_chirho)
        .map_err(|_| Gd7ObligationProcessingRefusalChirho::SerializationChirho)?;
    if bytes_chirho.len() > MAX_GD7_OBLIGATION_PROCESSING_BYTES_CHIRHO {
        return Err(Gd7ObligationProcessingRefusalChirho::OversizedStateChirho);
    }
    Ok(bytes_chirho)
}

fn deserialize_state_chirho(
    bytes_chirho: &[u8],
) -> Result<Gd7ObligationProcessingStateChirho, Gd7ObligationProcessingRefusalChirho> {
    if bytes_chirho.len() > MAX_GD7_OBLIGATION_PROCESSING_BYTES_CHIRHO {
        return Err(Gd7ObligationProcessingRefusalChirho::OversizedStateChirho);
    }
    let mut state_chirho: Gd7ObligationProcessingStateChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_| Gd7ObligationProcessingRefusalChirho::InvalidStateChirho)?;
    if state_chirho.schema_chirho != GD7_OBLIGATION_PROCESSING_SCHEMA_V1_CHIRHO
        && state_chirho.schema_chirho != GD7_OBLIGATION_PROCESSING_SCHEMA_V2_CHIRHO
    {
        return Err(Gd7ObligationProcessingRefusalChirho::InvalidStateChirho);
    }
    if state_chirho.schema_chirho == GD7_OBLIGATION_PROCESSING_SCHEMA_V1_CHIRHO {
        state_chirho.schema_chirho = GD7_OBLIGATION_PROCESSING_SCHEMA_V2_CHIRHO.to_owned();
    }
    validate_state_inputs_chirho(
        &state_chirho.mint_identity_digest_chirho,
        &state_chirho.obligation_receipt_ref_chirho,
        &state_chirho.canonical_obligation_digest_chirho,
        &state_chirho.inverse_authority_ref_chirho,
        &state_chirho.action_idempotency_key_chirho,
    )?;
    if matches!(
        state_chirho.terminal_progress_chirho,
        Gd7ObligationTerminalProgressChirho::JournalRecordedChirho
            | Gd7ObligationTerminalProgressChirho::CompletedChirho
    ) && state_chirho.journal_receipt_chirho.is_none()
    {
        return Err(Gd7ObligationProcessingRefusalChirho::InvalidStateChirho);
    }
    if state_chirho.provider_observation_chirho.is_some()
        && state_chirho.provider_intent_chirho.is_none()
    {
        return Err(Gd7ObligationProcessingRefusalChirho::InvalidStateChirho);
    }
    Ok(state_chirho)
}

fn validate_state_inputs_chirho(
    mint_identity_digest_chirho: &str,
    obligation_receipt_ref_chirho: &str,
    canonical_obligation_digest_chirho: &str,
    inverse_authority_ref_chirho: &str,
    action_idempotency_key_chirho: &str,
) -> Result<(), Gd7ObligationProcessingRefusalChirho> {
    if !is_lower_hex_digest_chirho(mint_identity_digest_chirho)
        || !is_lower_hex_digest_chirho(canonical_obligation_digest_chirho)
    {
        return Err(Gd7ObligationProcessingRefusalChirho::InvalidReferenceChirho);
    }
    validate_reference_chirho(obligation_receipt_ref_chirho)?;
    validate_reference_chirho(inverse_authority_ref_chirho)?;
    validate_reference_chirho(action_idempotency_key_chirho)
}

fn validate_reference_chirho(
    reference_chirho: &str,
) -> Result<(), Gd7ObligationProcessingRefusalChirho> {
    if reference_chirho.is_empty()
        || reference_chirho.len() > MAX_GD7_OBLIGATION_PROCESSING_REFERENCE_BYTES_CHIRHO
        || reference_chirho.chars().any(char::is_control)
    {
        return Err(Gd7ObligationProcessingRefusalChirho::InvalidReferenceChirho);
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::FsLedgerStorageChirho;
    use std::fs;
    use std::path::PathBuf;

    struct TestDispositionVerifierChirho;

    impl Gd7ReconciliationVerifierPortChirho for TestDispositionVerifierChirho {
        fn key_id_chirho(&self) -> String {
            "operator-key-chirho".to_owned()
        }

        fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
            let digest_chirho = blake3::hash(canonical_unsigned_chirho.as_bytes()).to_hex();
            sig_chirho == format!("sig-{}", digest_chirho)
        }
    }

    const MINT_CHIRHO: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OBLIGATION_CHIRHO: &str =
        "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";

    fn storage_chirho(test_name_chirho: &str) -> (PathBuf, FsLedgerStorageChirho) {
        let directory_chirho = std::env::temp_dir().join(format!(
            "cairn-gd7-obligation-processing-{}-{}-{}",
            std::process::id(),
            test_name_chirho,
            MINT_CHIRHO
        ));
        let _ = fs::remove_dir_all(&directory_chirho);
        fs::create_dir_all(&directory_chirho).expect("temporary storage");
        let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&directory_chirho)
            .expect("open temporary storage");
        (directory_chirho, storage_chirho)
    }

    fn signed_disposition_chirho(
        mint_identity_digest_chirho: &str,
        operator_key_id_chirho: &str,
        disposed_at_unix_seconds_chirho: u64,
        compensating_effect_ref_chirho: Option<String>,
        no_action_reason_chirho: Option<String>,
    ) -> Gd7HeldManualDispositionChirho {
        let mut disposition_chirho = Gd7HeldManualDispositionChirho::new_chirho(
            mint_identity_digest_chirho.to_owned(),
            operator_key_id_chirho.to_owned(),
            disposed_at_unix_seconds_chirho,
            compensating_effect_ref_chirho,
            no_action_reason_chirho,
            String::new(),
        );
        let unsigned_bytes_chirho = serde_json::to_vec(&disposition_chirho).unwrap();
        let digest_chirho = blake3::hash(&unsigned_bytes_chirho).to_hex();
        disposition_chirho.sig_chirho = format!("sig-{}", digest_chirho);
        disposition_chirho
    }

    #[test]
    fn restart_resume_and_same_action_retry_preserve_one_state_chirho() {
        let (directory_chirho, storage_chirho) = storage_chirho("restart");
        let initial_chirho = create_or_load_gd7_obligation_processing_state_chirho(
            &storage_chirho,
            MINT_CHIRHO,
            "receipt-5a-chirho",
            OBLIGATION_CHIRHO,
            "inverse-authority-chirho",
            "action-1-chirho",
        )
        .expect("create state");
        let intent_chirho = record_gd7_provider_intent_chirho(
            &storage_chirho,
            &initial_chirho,
            "provider-key-restart-chirho",
            OBLIGATION_CHIRHO,
        )
        .expect("persist provider intent");
        let observed_chirho = record_gd7_provider_observation_chirho(
            &storage_chirho,
            &intent_chirho,
            "provider-observation-chirho",
            "effect-restart-chirho",
        )
        .expect("persist observation");
        let journaled_chirho = record_gd7_journal_receipt_chirho(
            &storage_chirho,
            &observed_chirho,
            "journal-receipt-chirho",
        )
        .expect("persist receipt");
        let completed_chirho =
            mark_gd7_obligation_completed_chirho(&storage_chirho, &journaled_chirho)
                .expect("persist terminal state");
        let reopened_chirho =
            load_gd7_obligation_processing_state_chirho(&storage_chirho, MINT_CHIRHO)
                .expect("reopen state");
        let retry_chirho = create_or_load_gd7_obligation_processing_state_chirho(
            &storage_chirho,
            MINT_CHIRHO,
            "receipt-5a-chirho",
            OBLIGATION_CHIRHO,
            "inverse-authority-chirho",
            "action-1-chirho",
        )
        .expect("same action retry");
        assert_eq!(reopened_chirho, completed_chirho);
        assert_eq!(retry_chirho, completed_chirho);
        fs::remove_dir_all(directory_chirho).expect("remove temporary storage");
    }

    #[test]
    fn distinct_action_or_obligation_refuses_without_replacing_state_chirho() {
        let (directory_chirho, storage_chirho) = storage_chirho("collision");
        create_or_load_gd7_obligation_processing_state_chirho(
            &storage_chirho,
            MINT_CHIRHO,
            "receipt-5a-chirho",
            OBLIGATION_CHIRHO,
            "inverse-authority-chirho",
            "action-1-chirho",
        )
        .expect("create state");
        let action_error_chirho = create_or_load_gd7_obligation_processing_state_chirho(
            &storage_chirho,
            MINT_CHIRHO,
            "receipt-5a-chirho",
            OBLIGATION_CHIRHO,
            "inverse-authority-chirho",
            "action-2-chirho",
        )
        .expect_err("distinct action must collide");
        assert_eq!(
            action_error_chirho,
            Gd7ObligationProcessingRefusalChirho::StateCollisionChirho
        );
        fs::remove_dir_all(directory_chirho).expect("remove temporary storage");
    }

    #[test]
    fn foreign_deserialized_state_refuses_closed_chirho() {
        let (directory_chirho, storage_chirho) = storage_chirho("foreign");
        let path_chirho = gd7_obligation_processing_state_path_chirho(MINT_CHIRHO).unwrap();
        storage_chirho
            .create_durable_chirho(&path_chirho, br#"{"schema_chirho":"foreign-v1-chirho"}"#)
            .expect("plant foreign state");
        let error_chirho =
            load_gd7_obligation_processing_state_chirho(&storage_chirho, MINT_CHIRHO)
                .expect_err("foreign state must refuse");
        assert_eq!(
            error_chirho,
            Gd7ObligationProcessingRefusalChirho::InvalidStateChirho
        );
        let display_records_chirho =
            load_gd7_obligation_processing_for_display_chirho(&storage_chirho)
                .expect("display loader preserves invalid rows");
        assert_eq!(display_records_chirho.len(), 1);
        assert!(!display_records_chirho[0].valid_chirho);
        assert!(display_records_chirho[0].state_chirho.is_none());
        fs::remove_dir_all(directory_chirho).expect("remove temporary storage");
    }

    #[test]
    fn each_durable_transition_failpoint_applies_before_write_and_resumes_chirho() {
        let (directory_chirho, storage_chirho) = storage_chirho("failpoints");
        let initial_chirho = create_or_load_gd7_obligation_processing_state_chirho(
            &storage_chirho,
            MINT_CHIRHO,
            "receipt-5a-chirho",
            OBLIGATION_CHIRHO,
            "inverse-authority-chirho",
            "action-failpoints-chirho",
        )
        .expect("create state");
        let intent_chirho = record_gd7_provider_intent_chirho(
            &storage_chirho,
            &initial_chirho,
            "provider-key-failpoint-chirho",
            OBLIGATION_CHIRHO,
        )
        .expect("persist provider intent");
        arm_next_durable_transition_failpoint_chirho();
        assert_eq!(
            record_gd7_provider_observation_chirho(
                &storage_chirho,
                &intent_chirho,
                "provider-failpoint-chirho",
                "effect-failpoint-chirho"
            )
            .expect_err("provider transition failpoint must apply"),
            Gd7ObligationProcessingRefusalChirho::CrashInjectedChirho
        );
        let reopened_initial_chirho =
            load_gd7_obligation_processing_state_chirho(&storage_chirho, MINT_CHIRHO)
                .expect("reopen after provider failpoint");
        assert_eq!(
            reopened_initial_chirho.terminal_progress_chirho(),
            Gd7ObligationTerminalProgressChirho::ProviderIntentPersistedChirho
        );
        let observed_chirho = record_gd7_provider_observation_chirho(
            &storage_chirho,
            &reopened_initial_chirho,
            "provider-failpoint-chirho",
            "effect-failpoint-chirho",
        )
        .expect("retry provider transition");
        arm_next_durable_transition_failpoint_chirho();
        assert_eq!(
            record_gd7_journal_receipt_chirho(
                &storage_chirho,
                &observed_chirho,
                "journal-failpoint-chirho"
            )
            .expect_err("journal transition failpoint must apply"),
            Gd7ObligationProcessingRefusalChirho::CrashInjectedChirho
        );
        let reopened_observed_chirho =
            load_gd7_obligation_processing_state_chirho(&storage_chirho, MINT_CHIRHO)
                .expect("reopen after journal failpoint");
        let journaled_chirho = record_gd7_journal_receipt_chirho(
            &storage_chirho,
            &reopened_observed_chirho,
            "journal-failpoint-chirho",
        )
        .expect("retry journal transition");
        arm_next_durable_transition_failpoint_chirho();
        assert_eq!(
            mark_gd7_obligation_completed_chirho(&storage_chirho, &journaled_chirho)
                .expect_err("completion transition failpoint must apply"),
            Gd7ObligationProcessingRefusalChirho::CrashInjectedChirho
        );
        let reopened_journaled_chirho =
            load_gd7_obligation_processing_state_chirho(&storage_chirho, MINT_CHIRHO)
                .expect("reopen after completion failpoint");
        let completed_chirho =
            mark_gd7_obligation_completed_chirho(&storage_chirho, &reopened_journaled_chirho)
                .expect("retry completion transition");
        assert_eq!(
            completed_chirho.terminal_progress_chirho(),
            Gd7ObligationTerminalProgressChirho::CompletedChirho
        );
        fs::remove_dir_all(directory_chirho).expect("remove temporary storage");
    }

    #[test]
    fn held_manual_observation_refuses_by_name_without_state_move_chirho() {
        let (directory_chirho, storage_chirho) = storage_chirho("held-observation");
        let initial_chirho = create_or_load_gd7_obligation_processing_state_chirho(
            &storage_chirho,
            MINT_CHIRHO,
            "receipt-5a-chirho",
            OBLIGATION_CHIRHO,
            "inverse-authority-chirho",
            "action-held-observation-chirho",
        )
        .expect("create state");
        let held_chirho = mark_gd7_obligation_held_manual_chirho(&storage_chirho, &initial_chirho)
            .expect("persist held manual state");
        let error_chirho = record_gd7_provider_observation_chirho(
            &storage_chirho,
            &held_chirho,
            "provider-after-held-chirho",
            "effect-after-held-chirho",
        )
        .expect_err("held manual observation must refuse");
        assert_eq!(
            error_chirho,
            Gd7ObligationProcessingRefusalChirho::InvalidStateChirho
        );
        assert_eq!(
            load_gd7_obligation_processing_state_chirho(&storage_chirho, MINT_CHIRHO)
                .expect("reload held state")
                .terminal_progress_chirho(),
            Gd7ObligationTerminalProgressChirho::HeldManualChirho
        );
        fs::remove_dir_all(directory_chirho).expect("remove temporary storage");
    }

    #[test]
    fn held_manual_journal_receipt_refuses_by_name_without_state_move_chirho() {
        let (directory_chirho, storage_chirho) = storage_chirho("held-journal");
        let initial_chirho = create_or_load_gd7_obligation_processing_state_chirho(
            &storage_chirho,
            MINT_CHIRHO,
            "receipt-5a-chirho",
            OBLIGATION_CHIRHO,
            "inverse-authority-chirho",
            "action-held-journal-chirho",
        )
        .expect("create state");
        let held_chirho = mark_gd7_obligation_held_manual_chirho(&storage_chirho, &initial_chirho)
            .expect("persist held manual state");
        let error_chirho = record_gd7_journal_receipt_chirho(
            &storage_chirho,
            &held_chirho,
            "journal-after-held-chirho",
        )
        .expect_err("held manual journal receipt must refuse");
        assert_eq!(
            error_chirho,
            Gd7ObligationProcessingRefusalChirho::InvalidStateChirho
        );
        assert_eq!(
            load_gd7_obligation_processing_state_chirho(&storage_chirho, MINT_CHIRHO)
                .expect("reload held state")
                .terminal_progress_chirho(),
            Gd7ObligationTerminalProgressChirho::HeldManualChirho
        );
        fs::remove_dir_all(directory_chirho).expect("remove temporary storage");
    }

    #[test]
    fn held_manual_completion_refuses_by_name_without_state_move_chirho() {
        let (directory_chirho, storage_chirho) = storage_chirho("held-completion");
        let initial_chirho = create_or_load_gd7_obligation_processing_state_chirho(
            &storage_chirho,
            MINT_CHIRHO,
            "receipt-5a-chirho",
            OBLIGATION_CHIRHO,
            "inverse-authority-chirho",
            "action-held-completion-chirho",
        )
        .expect("create state");
        let held_chirho = mark_gd7_obligation_held_manual_chirho(&storage_chirho, &initial_chirho)
            .expect("persist held manual state");
        let error_chirho = mark_gd7_obligation_completed_chirho(&storage_chirho, &held_chirho)
            .expect_err("held manual completion must refuse");
        assert_eq!(
            error_chirho,
            Gd7ObligationProcessingRefusalChirho::InvalidStateChirho
        );
        assert_eq!(
            load_gd7_obligation_processing_state_chirho(&storage_chirho, MINT_CHIRHO)
                .expect("reload held state")
                .terminal_progress_chirho(),
            Gd7ObligationTerminalProgressChirho::HeldManualChirho
        );
        fs::remove_dir_all(directory_chirho).expect("remove temporary storage");
    }

    #[test]
    fn held_manual_disposition_is_signed_one_way_and_tamper_refuses_chirho() {
        let (directory_chirho, storage_chirho) = storage_chirho("held-disposition");
        let initial_chirho = create_or_load_gd7_obligation_processing_state_chirho(
            &storage_chirho,
            MINT_CHIRHO,
            "receipt-5a-chirho",
            OBLIGATION_CHIRHO,
            "inverse-authority-chirho",
            "action-held-disposition-chirho",
        )
        .expect("create state");
        let held_chirho = mark_gd7_obligation_held_manual_chirho(&storage_chirho, &initial_chirho)
            .expect("persist held state");
        let verifier_chirho = TestDispositionVerifierChirho;
        let valid_chirho = signed_disposition_chirho(
            MINT_CHIRHO,
            &verifier_chirho.key_id_chirho(),
            1_700_000_000,
            None,
            Some("provider outcome unavailable; no action taken-chirho".to_owned()),
        );
        let disposed_chirho = dispose_gd7_obligation_held_manual_chirho(
            &storage_chirho,
            &held_chirho,
            valid_chirho.clone(),
            &verifier_chirho,
        )
        .expect("valid signed disposition");
        assert!(disposed_chirho.held_manual_disposition_chirho().is_some());
        assert_eq!(
            dispose_gd7_obligation_held_manual_chirho(
                &storage_chirho,
                &disposed_chirho,
                signed_disposition_chirho(
                    MINT_CHIRHO,
                    &verifier_chirho.key_id_chirho(),
                    1_700_000_001,
                    Some("effect-ref-chirho".to_owned()),
                    None,
                ),
                &verifier_chirho,
            )
            .expect_err("disposed state must not be overwritten"),
            Gd7ObligationProcessingRefusalChirho::StateCollisionChirho
        );
        for tampered_chirho in [
            {
                let mut value_chirho = valid_chirho.clone();
                value_chirho.mint_identity_digest_chirho = OBLIGATION_CHIRHO.to_owned();
                value_chirho
            },
            {
                let mut value_chirho = valid_chirho.clone();
                value_chirho.operator_key_id_chirho = "other-operator-chirho".to_owned();
                value_chirho
            },
            {
                let mut value_chirho = valid_chirho.clone();
                value_chirho.no_action_reason_chirho = Some("different-reason-chirho".to_owned());
                value_chirho
            },
            {
                let mut value_chirho = signed_disposition_chirho(
                    MINT_CHIRHO,
                    &verifier_chirho.key_id_chirho(),
                    1_700_000_003,
                    Some("effect-original-chirho".to_owned()),
                    None,
                );
                value_chirho.compensating_effect_ref_chirho =
                    Some("effect-tampered-chirho".to_owned());
                value_chirho
            },
        ] {
            assert_eq!(
                dispose_gd7_obligation_held_manual_chirho(
                    &storage_chirho,
                    &held_chirho,
                    tampered_chirho,
                    &verifier_chirho,
                )
                .expect_err("content tamper with original signature must refuse"),
                Gd7ObligationProcessingRefusalChirho::InvalidStateChirho
            );
        }
        for illegal_chirho in [
            signed_disposition_chirho(
                MINT_CHIRHO,
                &verifier_chirho.key_id_chirho(),
                1_700_000_004,
                Some("effect-both-chirho".to_owned()),
                Some("both-fields-chirho".to_owned()),
            ),
            signed_disposition_chirho(
                MINT_CHIRHO,
                &verifier_chirho.key_id_chirho(),
                1_700_000_005,
                None,
                None,
            ),
        ] {
            assert_eq!(
                dispose_gd7_obligation_held_manual_chirho(
                    &storage_chirho,
                    &held_chirho,
                    illegal_chirho,
                    &verifier_chirho,
                )
                .expect_err("disposition must contain exactly one evidence shape"),
                Gd7ObligationProcessingRefusalChirho::InvalidStateChirho
            );
        }
        fs::remove_dir_all(directory_chirho).expect("remove disposition storage");
    }

    #[test]
    fn unknown_v2_state_field_refuses_closed_chirho() {
        let (directory_chirho, storage_chirho) = storage_chirho("unknown-field");
        let initial_chirho = create_or_load_gd7_obligation_processing_state_chirho(
            &storage_chirho,
            MINT_CHIRHO,
            "receipt-5a-chirho",
            OBLIGATION_CHIRHO,
            "inverse-authority-chirho",
            "action-unknown-field-chirho",
        )
        .expect("create state");
        let path_chirho = gd7_obligation_processing_state_path_chirho(MINT_CHIRHO).unwrap();
        let mut state_value_chirho = serde_json::to_value(initial_chirho).unwrap();
        state_value_chirho["foreign_field_chirho"] = serde_json::json!("must-refuse-chirho");
        storage_chirho
            .atomic_write_chirho(
                &path_chirho,
                &serde_json::to_vec(&state_value_chirho).unwrap(),
            )
            .expect("plant unknown field");
        assert_eq!(
            load_gd7_obligation_processing_state_chirho(&storage_chirho, MINT_CHIRHO)
                .expect_err("unknown state field must refuse"),
            Gd7ObligationProcessingRefusalChirho::InvalidStateChirho
        );
        fs::remove_dir_all(directory_chirho).expect("remove unknown-field storage");
    }
}
