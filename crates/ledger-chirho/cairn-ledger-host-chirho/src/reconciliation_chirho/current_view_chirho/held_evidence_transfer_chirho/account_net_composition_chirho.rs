// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Read-only composition proof for one exact GD7 winner account-net view.
//!
//! This module independently folds the verified winner suffix onto the winner-signed fork
//! baseline and requires exact equality with the separately transferred winner view. The result
//! is evidence only: it cannot install a journal, move a ref, adopt, compensate, or enable writes.
//! The baseline is deliberately account-net-scoped and is not a general ledger checkpoint.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

use super::super::adoption_chirho::{
    verify_complete_gd7_held_winner_view_chain_with_rows_chirho,
    Gd7HeldWinnerViewVerificationRefusalChirho,
};
use super::super::winner_history_chirho::verify_complete_gd7_winner_history_chain_with_records_chirho;
use super::super::{
    account_net_projection_fold_ref_chirho, verify_complete_gd7_fork_baseline_chirho,
    Gd7ForkBaselineRefusalChirho, Gd7HeldViewTransferIdentityChirho, Gd7WinnerHistoryRefusalChirho,
};
use super::{
    Gd7HeldEvidenceTransferIdentityChirho, Gd7HeldEvidenceTransferStoreRefusalChirho,
    Gd7WinnerEvidenceManifestChirho,
};
use crate::reconciliation_chirho::{
    Gd7LedgerRecordVerifierPortChirho, Gd7ReconciliationSignerPortChirho,
    Gd7ReconciliationVerifierPortChirho,
};
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;
use cairn_ledger_model_chirho::account_state_chirho::{fold_leg_chirho, AccountStateChirho};
use cairn_ledger_model_chirho::ids_chirho::AccountIdChirho;
use cairn_ledger_model_chirho::record_chirho::{LedgerRecordChirho, LegPostStateChirho};
use cairn_ledger_read_model_chirho::{
    account_net_projection_row_chirho, canonical_account_net_projection_view_chirho,
    AccountNetProjectionViewChirho, ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO,
};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

pub(super) struct Gd7AccountNetCompositionInputsChirho<'input_chirho> {
    pub(super) storage_chirho: &'input_chirho dyn LedgerStoragePortChirho,
    pub(super) held_signer_chirho: &'input_chirho dyn Gd7ReconciliationSignerPortChirho,
    pub(super) winner_verifier_chirho: &'input_chirho dyn Gd7ReconciliationVerifierPortChirho,
    pub(super) winner_ledger_verifier_chirho: &'input_chirho dyn Gd7LedgerRecordVerifierPortChirho,
    pub(super) identity_chirho: &'input_chirho Gd7HeldEvidenceTransferIdentityChirho,
    pub(super) evidence_checkpoint_ref_chirho: &'input_chirho str,
    pub(super) manifest_chirho: &'input_chirho Gd7WinnerEvidenceManifestChirho,
}

/// Opaque proof that three independently verified artifact families compose to one exact
/// account-net view.
///
/// Private fields and no serde/conversion implementation keep this value from becoming caller-made
/// authority. A later held actor must still recheck freshness, the accepted winner barrier, and
/// the eventual branch-install checkpoint before any adoption transition.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedGd7AccountNetCompositionChirho {
    evidence_checkpoint_ref_chirho: String,
    held_view_checkpoint_ref_chirho: String,
    held_view_bundle_root_ref_chirho: String,
    winner_history_root_ref_chirho: String,
    fork_baseline_root_ref_chirho: String,
    applied_record_count_chirho: u64,
    matched_row_count_chirho: u64,
    canonical_projection_bytes_chirho: Vec<u8>,
}

impl VerifiedGd7AccountNetCompositionChirho {
    pub fn evidence_checkpoint_ref_chirho(&self) -> &str {
        &self.evidence_checkpoint_ref_chirho
    }

    pub fn held_view_checkpoint_ref_chirho(&self) -> &str {
        &self.held_view_checkpoint_ref_chirho
    }

    pub fn held_view_bundle_root_ref_chirho(&self) -> &str {
        &self.held_view_bundle_root_ref_chirho
    }

    pub fn winner_history_root_ref_chirho(&self) -> &str {
        &self.winner_history_root_ref_chirho
    }

    pub fn fork_baseline_root_ref_chirho(&self) -> &str {
        &self.fork_baseline_root_ref_chirho
    }

    pub fn applied_record_count_chirho(&self) -> u64 {
        self.applied_record_count_chirho
    }

    pub fn matched_row_count_chirho(&self) -> u64 {
        self.matched_row_count_chirho
    }

    pub(crate) fn canonical_projection_bytes_chirho(&self) -> &[u8] {
        &self.canonical_projection_bytes_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7AccountNetCompositionRefusalChirho {
    EvidenceStoreChirho(Gd7HeldEvidenceTransferStoreRefusalChirho),
    WinnerHistoryChirho(Gd7WinnerHistoryRefusalChirho),
    ForkBaselineChirho(Gd7ForkBaselineRefusalChirho),
    HeldWinnerViewChirho(Gd7HeldWinnerViewVerificationRefusalChirho),
    IncompleteEvidenceChirho,
    StaleEvidenceChirho,
    InvalidEvidenceBindingChirho,
    ArithmeticOverflowChirho,
    StoredPostMismatchChirho,
    InvalidProjectedStateChirho,
    CurrentViewMismatchChirho,
}

impl fmt::Display for Gd7AccountNetCompositionRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EvidenceStoreChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 held evidence store refused: {error_chirho}"
                )
            }
            Self::WinnerHistoryChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 winner history refused: {error_chirho}"
                )
            }
            Self::ForkBaselineChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 fork baseline refused: {error_chirho}"
                )
            }
            Self::HeldWinnerViewChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 held winner view refused: {error_chirho}"
                )
            }
            Self::IncompleteEvidenceChirho => {
                formatter_chirho.write_str("GD7 held evidence transfer is incomplete")
            }
            Self::StaleEvidenceChirho => formatter_chirho
                .write_str("GD7 held evidence checkpoint changed during composition"),
            Self::InvalidEvidenceBindingChirho => {
                formatter_chirho.write_str("GD7 account-net evidence identities do not match")
            }
            Self::ArithmeticOverflowChirho => {
                formatter_chirho.write_str("GD7 account-net composition arithmetic refused")
            }
            Self::StoredPostMismatchChirho => formatter_chirho
                .write_str("GD7 winner-history stored post differs from the independent fold"),
            Self::InvalidProjectedStateChirho => {
                formatter_chirho.write_str("GD7 composed account-net state is invalid")
            }
            Self::CurrentViewMismatchChirho => formatter_chirho
                .write_str("GD7 composed account-net rows differ from the accepted winner view"),
        }
    }
}

impl Error for Gd7AccountNetCompositionRefusalChirho {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::EvidenceStoreChirho(error_chirho) => Some(error_chirho),
            Self::WinnerHistoryChirho(error_chirho) => Some(error_chirho),
            Self::ForkBaselineChirho(error_chirho) => Some(error_chirho),
            Self::HeldWinnerViewChirho(error_chirho) => Some(error_chirho),
            _ => None,
        }
    }
}

impl From<Gd7HeldEvidenceTransferStoreRefusalChirho> for Gd7AccountNetCompositionRefusalChirho {
    fn from(error_chirho: Gd7HeldEvidenceTransferStoreRefusalChirho) -> Self {
        Self::EvidenceStoreChirho(error_chirho)
    }
}

impl From<Gd7WinnerHistoryRefusalChirho> for Gd7AccountNetCompositionRefusalChirho {
    fn from(error_chirho: Gd7WinnerHistoryRefusalChirho) -> Self {
        Self::WinnerHistoryChirho(error_chirho)
    }
}

impl From<Gd7ForkBaselineRefusalChirho> for Gd7AccountNetCompositionRefusalChirho {
    fn from(error_chirho: Gd7ForkBaselineRefusalChirho) -> Self {
        Self::ForkBaselineChirho(error_chirho)
    }
}

impl From<Gd7HeldWinnerViewVerificationRefusalChirho> for Gd7AccountNetCompositionRefusalChirho {
    fn from(error_chirho: Gd7HeldWinnerViewVerificationRefusalChirho) -> Self {
        Self::HeldWinnerViewChirho(error_chirho)
    }
}

pub(super) fn verify_gd7_account_net_composition_chirho(
    inputs_chirho: Gd7AccountNetCompositionInputsChirho<'_>,
) -> Result<VerifiedGd7AccountNetCompositionChirho, Gd7AccountNetCompositionRefusalChirho> {
    validate_exact_artifact_bindings_chirho(
        inputs_chirho.identity_chirho,
        inputs_chirho.manifest_chirho,
    )?;
    let reconciliation_identity_chirho =
        &inputs_chirho.identity_chirho.reconciliation_identity_chirho;
    let history_identity_chirho = &inputs_chirho
        .manifest_chirho
        .winner_history_root_chirho
        .identity_chirho;
    let baseline_identity_chirho = &inputs_chirho
        .manifest_chirho
        .fork_baseline_root_chirho
        .identity_chirho;

    let baseline_chirho = verify_complete_gd7_fork_baseline_chirho(
        inputs_chirho.storage_chirho,
        &inputs_chirho
            .manifest_chirho
            .fork_baseline_root_object_digest_chirho,
        baseline_identity_chirho,
        inputs_chirho.winner_verifier_chirho,
    )?;
    let fork_baseline_root_ref_chirho = baseline_chirho
        .root_chirho()
        .object_digest_chirho()
        .to_owned();
    let mut head_states_chirho = baseline_chirho.into_head_states_chirho();
    let mut fold_refusal_chirho = None;
    let mut applied_record_count_chirho = 0_u64;
    let history_chirho = verify_complete_gd7_winner_history_chain_with_records_chirho(
        inputs_chirho.storage_chirho,
        &inputs_chirho
            .manifest_chirho
            .winner_history_root_object_digest_chirho,
        history_identity_chirho,
        inputs_chirho.winner_verifier_chirho,
        inputs_chirho.winner_ledger_verifier_chirho,
        |record_chirho| {
            if fold_refusal_chirho.is_some() {
                return;
            }
            if let Err(error_chirho) = apply_record_chirho(&mut head_states_chirho, record_chirho) {
                fold_refusal_chirho = Some(error_chirho);
                return;
            }
            match applied_record_count_chirho.checked_add(1) {
                Some(next_chirho) => applied_record_count_chirho = next_chirho,
                None => {
                    fold_refusal_chirho =
                        Some(Gd7AccountNetCompositionRefusalChirho::ArithmeticOverflowChirho);
                }
            }
        },
    )?;
    if let Some(error_chirho) = fold_refusal_chirho {
        return Err(error_chirho);
    }
    if applied_record_count_chirho
        != history_chirho
            .root_chirho()
            .root_chirho()
            .record_count_chirho
    {
        return Err(Gd7AccountNetCompositionRefusalChirho::ArithmeticOverflowChirho);
    }
    let winner_history_root_ref_chirho = history_chirho
        .root_chirho()
        .object_digest_chirho()
        .to_owned();

    let held_view_identity_chirho = Gd7HeldViewTransferIdentityChirho {
        consistency_group_digest_chirho: reconciliation_identity_chirho
            .consistency_group_digest_chirho
            .clone(),
        reconciliation_checkpoint_ref_chirho: inputs_chirho
            .identity_chirho
            .reconciliation_checkpoint_ref_chirho
            .clone(),
        winner_node_chirho: reconciliation_identity_chirho.winner_node_chirho.clone(),
        held_node_chirho: reconciliation_identity_chirho.held_node_chirho.clone(),
        winner_term_chirho: reconciliation_identity_chirho.winner_term_chirho,
    };
    let mut expected_rows_chirho = head_states_chirho.iter();
    let mut row_refusal_chirho = None;
    let mut matched_row_count_chirho = 0_u64;
    let held_view_chirho = verify_complete_gd7_held_winner_view_chain_with_rows_chirho(
        inputs_chirho.storage_chirho,
        inputs_chirho.held_signer_chirho,
        inputs_chirho.winner_verifier_chirho,
        held_view_identity_chirho,
        &inputs_chirho
            .identity_chirho
            .held_view_transfer_checkpoint_ref_chirho,
        |actual_row_chirho| {
            if row_refusal_chirho.is_some() {
                return;
            }
            let Some((account_chirho, post_chirho)) = expected_rows_chirho.next() else {
                row_refusal_chirho =
                    Some(Gd7AccountNetCompositionRefusalChirho::CurrentViewMismatchChirho);
                return;
            };
            let expected_row_chirho =
                match account_net_projection_row_chirho(account_chirho, post_chirho) {
                    Ok(row_chirho) => row_chirho,
                    Err(_error_chirho) => {
                        row_refusal_chirho = Some(
                            Gd7AccountNetCompositionRefusalChirho::InvalidProjectedStateChirho,
                        );
                        return;
                    }
                };
            if expected_row_chirho != *actual_row_chirho {
                row_refusal_chirho =
                    Some(Gd7AccountNetCompositionRefusalChirho::CurrentViewMismatchChirho);
                return;
            }
            match matched_row_count_chirho.checked_add(1) {
                Some(next_chirho) => matched_row_count_chirho = next_chirho,
                None => {
                    row_refusal_chirho =
                        Some(Gd7AccountNetCompositionRefusalChirho::ArithmeticOverflowChirho);
                }
            }
        },
    )?;
    let held_view_root_chirho = held_view_chirho.bundle_root_chirho();
    if held_view_chirho.consistency_group_digest_chirho()
        != reconciliation_identity_chirho.consistency_group_digest_chirho
        || held_view_chirho.winner_node_chirho()
            != reconciliation_identity_chirho.winner_node_chirho
        || held_view_chirho.held_node_chirho() != reconciliation_identity_chirho.held_node_chirho
        || held_view_chirho.winner_term_chirho()
            != reconciliation_identity_chirho.winner_term_chirho
        || held_view_root_chirho.projection_fold_ref_chirho
            != account_net_projection_fold_ref_chirho().0
        || held_view_root_chirho.winner_journal_genesis_digest_chirho
            != reconciliation_identity_chirho.winner_journal_genesis_digest_chirho
        || held_view_root_chirho.source_cut_chirho
            != reconciliation_identity_chirho.winner_journal_tail_chirho
    {
        return Err(Gd7AccountNetCompositionRefusalChirho::InvalidEvidenceBindingChirho);
    }
    if let Some(error_chirho) = row_refusal_chirho {
        return Err(error_chirho);
    }
    if expected_rows_chirho.next().is_some()
        || matched_row_count_chirho != held_view_chirho.received_row_count_chirho()
        || usize::try_from(matched_row_count_chirho)
            .map_err(|_| Gd7AccountNetCompositionRefusalChirho::ArithmeticOverflowChirho)?
            != head_states_chirho.len()
    {
        return Err(Gd7AccountNetCompositionRefusalChirho::CurrentViewMismatchChirho);
    }
    drop(expected_rows_chirho);
    let canonical_projection_bytes_chirho =
        canonical_account_net_projection_view_chirho(&AccountNetProjectionViewChirho {
            schema_chirho: ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO.to_owned(),
            rows_chirho: head_states_chirho
                .iter()
                .map(|(account_chirho, post_chirho)| {
                    account_net_projection_row_chirho(account_chirho, post_chirho)
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_error_chirho| {
                    Gd7AccountNetCompositionRefusalChirho::InvalidProjectedStateChirho
                })?,
        })
        .map_err(|_error_chirho| {
            Gd7AccountNetCompositionRefusalChirho::InvalidProjectedStateChirho
        })?;

    Ok(VerifiedGd7AccountNetCompositionChirho {
        evidence_checkpoint_ref_chirho: inputs_chirho.evidence_checkpoint_ref_chirho.to_owned(),
        held_view_checkpoint_ref_chirho: held_view_chirho
            .transfer_checkpoint_ref_chirho()
            .to_owned(),
        held_view_bundle_root_ref_chirho: held_view_chirho
            .bundle_root_object_digest_chirho()
            .to_owned(),
        winner_history_root_ref_chirho,
        fork_baseline_root_ref_chirho,
        applied_record_count_chirho,
        matched_row_count_chirho,
        canonical_projection_bytes_chirho,
    })
}

fn validate_exact_artifact_bindings_chirho(
    identity_chirho: &Gd7HeldEvidenceTransferIdentityChirho,
    manifest_chirho: &Gd7WinnerEvidenceManifestChirho,
) -> Result<(), Gd7AccountNetCompositionRefusalChirho> {
    let history_identity_chirho = &manifest_chirho.winner_history_root_chirho.identity_chirho;
    let baseline_identity_chirho = &manifest_chirho.fork_baseline_root_chirho.identity_chirho;
    if manifest_chirho.transfer_identity_chirho != *identity_chirho
        || history_identity_chirho.reconciliation_identity_chirho
            != identity_chirho.reconciliation_identity_chirho
        || baseline_identity_chirho.reconciliation_identity_chirho
            != identity_chirho.reconciliation_identity_chirho
        || history_identity_chirho.reconciliation_identity_chirho
            != baseline_identity_chirho.reconciliation_identity_chirho
        || history_identity_chirho.reconciliation_identity_digest_chirho
            != baseline_identity_chirho.reconciliation_identity_digest_chirho
        || history_identity_chirho.winner_handoff_attempt_digest_chirho
            != identity_chirho.winner_handoff_attempt_digest_chirho
        || baseline_identity_chirho.winner_handoff_attempt_digest_chirho
            != identity_chirho.winner_handoff_attempt_digest_chirho
    {
        return Err(Gd7AccountNetCompositionRefusalChirho::InvalidEvidenceBindingChirho);
    }
    Ok(())
}

fn apply_record_chirho(
    head_states_chirho: &mut BTreeMap<AccountIdChirho, LegPostStateChirho>,
    record_chirho: &LedgerRecordChirho,
) -> Result<(), Gd7AccountNetCompositionRefusalChirho> {
    for leg_chirho in &record_chirho.legs_chirho {
        let prior_chirho = head_states_chirho
            .get(&leg_chirho.account_chirho)
            .map(account_state_from_post_chirho)
            .unwrap_or_default();
        let next_chirho = fold_leg_chirho(
            prior_chirho,
            &leg_chirho.delta_chirho,
            leg_chirho.amount_chirho,
        )
        .ok_or(Gd7AccountNetCompositionRefusalChirho::ArithmeticOverflowChirho)?;
        let expected_post_chirho = post_from_account_state_chirho(next_chirho);
        if expected_post_chirho != leg_chirho.post_chirho {
            return Err(Gd7AccountNetCompositionRefusalChirho::StoredPostMismatchChirho);
        }
        head_states_chirho.insert(leg_chirho.account_chirho.clone(), expected_post_chirho);
    }
    Ok(())
}

fn account_state_from_post_chirho(post_chirho: &LegPostStateChirho) -> AccountStateChirho {
    AccountStateChirho {
        credits_chirho: post_chirho.credits_total_chirho,
        debits_chirho: post_chirho.debits_total_chirho,
        held_chirho: post_chirho.held_chirho,
    }
}

fn post_from_account_state_chirho(state_chirho: AccountStateChirho) -> LegPostStateChirho {
    LegPostStateChirho {
        credits_total_chirho: state_chirho.credits_chirho,
        debits_total_chirho: state_chirho.debits_chirho,
        held_chirho: state_chirho.held_chirho,
    }
}

#[cfg(test)]
#[path = "account_net_composition_tests_chirho.rs"]
mod account_net_composition_tests_chirho;

#[cfg(test)]
#[path = "adoption_materialization_tests_chirho.rs"]
mod adoption_materialization_tests_chirho;
