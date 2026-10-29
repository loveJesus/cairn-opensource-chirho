// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Signed positive-head transition receipts and crash recovery over caller-verified intents.

use crate::writer_head_chirho::{
    consistency_group_digest_chirho, verify_writer_fence_for_root_chirho,
    with_head_transition_scope_chirho, ConsistencyGroupIdChirho, PreparedFenceLowerBoundChirho,
    WriterFenceTokenChirho,
};
use anyhow::{bail, Context, Result};
use cairn_core_chirho::{
    model_chirho::HashChirho,
    refs_chirho::{self, HeadTransitionCommitOutcomeChirho, ReflogEntryChirho},
};
use cairn_seqlog_chirho::seqlog_chirho;
use cairn_signer_chirho::signer_chirho;
use serde::Serialize;
use std::path::{Component, Path};

pub const HEAD_TRANSITION_RECEIPT_SCHEMA_CHIRHO: &str = "head-transition-receipt-v1-chirho";
pub const HEAD_TRANSITION_ID_PREFIX_CHIRHO: &str = "head-transition-blake3-v1-chirho:";
pub const HEAD_TRANSITION_FAMILY_LINE_DIGEST_PREFIX_CHIRHO: &str =
    "head-transition-family-line-blake3-v1-chirho:";
pub const HEAD_TRANSITION_RECEIPT_CORE_DIGEST_PREFIX_CHIRHO: &str =
    "head-transition-receipt-core-blake3-v1-chirho:";
const HEAD_TRANSITION_ID_CONTEXT_CHIRHO: &str = "cairn-head-transition-id-v1-chirho";
const HEAD_TRANSITION_OPERATION_DIGEST_PREFIX_CHIRHO: &str =
    "head-transition-operation-blake3-v1-chirho:";

pub struct HeadTransitionIdentityInputChirho<'a> {
    pub family_log_chirho: &'a str,
    pub family_seq_chirho: u64,
    pub branch_chirho: &'a str,
    pub previous_chirho: &'a Option<HashChirho>,
    pub next_chirho: &'a HashChirho,
    pub reason_chirho: &'a str,
    pub operation_bytes_chirho: &'a [u8],
    pub prepared_fence_chirho: &'a WriterFenceTokenChirho,
    pub at_ms_chirho: u64,
}

pub struct PreparedFenceHeadTransitionIdentityInputChirho<'a> {
    pub family_log_chirho: &'a str,
    pub family_seq_chirho: u64,
    pub branch_chirho: &'a str,
    pub previous_chirho: &'a Option<HashChirho>,
    pub next_chirho: &'a HashChirho,
    pub reason_chirho: &'a str,
    pub operation_bytes_chirho: &'a [u8],
    pub prepared_fence_chirho: &'a PreparedFenceLowerBoundChirho,
    pub at_ms_chirho: u64,
}

pub struct PreparedHeadTransitionChirho {
    transition_id_chirho: String,
    family_log_chirho: String,
    family_seq_chirho: u64,
    family_line_digest_chirho: String,
    branch_chirho: String,
    previous_chirho: Option<HashChirho>,
    next_chirho: HashChirho,
    reason_chirho: String,
    writer_fence_group_digest_chirho: String,
    prepared_writer_fence_epoch_chirho: u64,
    prepared_root_binding_chirho: Option<PreparedFenceLowerBoundChirho>,
    at_ms_chirho: u64,
}

impl PreparedHeadTransitionChirho {
    pub fn transition_id_chirho(&self) -> &str {
        &self.transition_id_chirho
    }

    pub fn previous_chirho(&self) -> &Option<HashChirho> {
        &self.previous_chirho
    }

    pub fn next_chirho(&self) -> &HashChirho {
        &self.next_chirho
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadTransitionRecoveryOutcomeChirho {
    AppliedChirho,
    RepairedReflogChirho,
    AlreadyAppliedChirho,
}

pub fn derive_head_transition_id_chirho(
    input_chirho: &HeadTransitionIdentityInputChirho<'_>,
) -> Result<String> {
    derive_head_transition_id_from_parts_chirho(&identity_parts_from_token_chirho(input_chirho))
}

/// Derive the byte-identical V2 transition id from non-authoritative prepared-fence evidence.
pub fn derive_head_transition_id_from_prepared_fence_chirho(
    input_chirho: &PreparedFenceHeadTransitionIdentityInputChirho<'_>,
) -> Result<String> {
    derive_head_transition_id_from_parts_chirho(&identity_parts_from_evidence_chirho(input_chirho))
}

struct HeadTransitionIdentityPartsChirho<'a> {
    family_log_chirho: &'a str,
    family_seq_chirho: u64,
    branch_chirho: &'a str,
    previous_chirho: &'a Option<HashChirho>,
    next_chirho: &'a HashChirho,
    reason_chirho: &'a str,
    operation_bytes_chirho: &'a [u8],
    prepared_group_chirho: &'a ConsistencyGroupIdChirho,
    prepared_epoch_chirho: u64,
    at_ms_chirho: u64,
}

fn identity_parts_from_token_chirho<'a>(
    input_chirho: &'a HeadTransitionIdentityInputChirho<'a>,
) -> HeadTransitionIdentityPartsChirho<'a> {
    HeadTransitionIdentityPartsChirho {
        family_log_chirho: input_chirho.family_log_chirho,
        family_seq_chirho: input_chirho.family_seq_chirho,
        branch_chirho: input_chirho.branch_chirho,
        previous_chirho: input_chirho.previous_chirho,
        next_chirho: input_chirho.next_chirho,
        reason_chirho: input_chirho.reason_chirho,
        operation_bytes_chirho: input_chirho.operation_bytes_chirho,
        prepared_group_chirho: &input_chirho.prepared_fence_chirho.group_chirho,
        prepared_epoch_chirho: input_chirho.prepared_fence_chirho.epoch_chirho,
        at_ms_chirho: input_chirho.at_ms_chirho,
    }
}

fn identity_parts_from_evidence_chirho<'a>(
    input_chirho: &'a PreparedFenceHeadTransitionIdentityInputChirho<'a>,
) -> HeadTransitionIdentityPartsChirho<'a> {
    HeadTransitionIdentityPartsChirho {
        family_log_chirho: input_chirho.family_log_chirho,
        family_seq_chirho: input_chirho.family_seq_chirho,
        branch_chirho: input_chirho.branch_chirho,
        previous_chirho: input_chirho.previous_chirho,
        next_chirho: input_chirho.next_chirho,
        reason_chirho: input_chirho.reason_chirho,
        operation_bytes_chirho: input_chirho.operation_bytes_chirho,
        prepared_group_chirho: input_chirho.prepared_fence_chirho.group_chirho(),
        prepared_epoch_chirho: input_chirho.prepared_fence_chirho.epoch_chirho(),
        at_ms_chirho: input_chirho.at_ms_chirho,
    }
}

fn derive_head_transition_id_from_parts_chirho(
    input_chirho: &HeadTransitionIdentityPartsChirho<'_>,
) -> Result<String> {
    validate_identity_parts_chirho(input_chirho)?;
    #[derive(Serialize)]
    struct TransitionIdentityMessageChirho<'a> {
        schema_chirho: &'static str,
        family_log_chirho: &'a str,
        family_seq_chirho: u64,
        branch_chirho: &'a str,
        previous_chirho: &'a Option<HashChirho>,
        next_chirho: &'a HashChirho,
        reason_chirho: &'a str,
        operation_digest_chirho: String,
        writer_fence_group_digest_chirho: String,
        prepared_writer_fence_epoch_chirho: u64,
        at_ms_chirho: u64,
    }
    let operation_digest_chirho = prefixed_hash_chirho(
        HEAD_TRANSITION_OPERATION_DIGEST_PREFIX_CHIRHO,
        input_chirho.operation_bytes_chirho,
    );
    let message_chirho = serde_json::to_vec(&TransitionIdentityMessageChirho {
        schema_chirho: HEAD_TRANSITION_RECEIPT_SCHEMA_CHIRHO,
        family_log_chirho: input_chirho.family_log_chirho,
        family_seq_chirho: input_chirho.family_seq_chirho,
        branch_chirho: input_chirho.branch_chirho,
        previous_chirho: input_chirho.previous_chirho,
        next_chirho: input_chirho.next_chirho,
        reason_chirho: input_chirho.reason_chirho,
        operation_digest_chirho,
        writer_fence_group_digest_chirho: consistency_group_digest_chirho(
            input_chirho.prepared_group_chirho,
        )?,
        prepared_writer_fence_epoch_chirho: input_chirho.prepared_epoch_chirho,
        at_ms_chirho: input_chirho.at_ms_chirho,
    })?;
    Ok(format!(
        "{}{}",
        HEAD_TRANSITION_ID_PREFIX_CHIRHO,
        hex_bytes_chirho(&blake3::derive_key(
            HEAD_TRANSITION_ID_CONTEXT_CHIRHO,
            &message_chirho,
        ))
    ))
}

/// Bind a transition id to the exact canonical signed family row already verified by the caller.
pub fn bind_caller_verified_head_transition_chirho(
    input_chirho: &HeadTransitionIdentityInputChirho<'_>,
    transition_id_chirho: &str,
    canonical_signed_family_line_chirho: &[u8],
) -> Result<PreparedHeadTransitionChirho> {
    bind_caller_verified_head_transition_from_parts_chirho(
        &identity_parts_from_token_chirho(input_chirho),
        transition_id_chirho,
        canonical_signed_family_line_chirho,
        None,
    )
}

/// Bind an elected PREPARE row to its exact group, epoch, and canonical root observation.
pub fn bind_caller_verified_head_transition_from_prepared_fence_chirho(
    input_chirho: &PreparedFenceHeadTransitionIdentityInputChirho<'_>,
    transition_id_chirho: &str,
    canonical_signed_family_line_chirho: &[u8],
) -> Result<PreparedHeadTransitionChirho> {
    bind_caller_verified_head_transition_from_parts_chirho(
        &identity_parts_from_evidence_chirho(input_chirho),
        transition_id_chirho,
        canonical_signed_family_line_chirho,
        Some(input_chirho.prepared_fence_chirho.clone()),
    )
}

fn bind_caller_verified_head_transition_from_parts_chirho(
    input_chirho: &HeadTransitionIdentityPartsChirho<'_>,
    transition_id_chirho: &str,
    canonical_signed_family_line_chirho: &[u8],
    prepared_root_binding_chirho: Option<PreparedFenceLowerBoundChirho>,
) -> Result<PreparedHeadTransitionChirho> {
    let expected_transition_id_chirho = derive_head_transition_id_from_parts_chirho(input_chirho)?;
    if transition_id_chirho != expected_transition_id_chirho {
        bail!("head transition id does not match the canonical unsigned operation tuple");
    }
    if canonical_signed_family_line_chirho.is_empty() {
        bail!("head transition canonical signed family line must not be empty");
    }
    Ok(PreparedHeadTransitionChirho {
        transition_id_chirho: transition_id_chirho.to_string(),
        family_log_chirho: input_chirho.family_log_chirho.to_string(),
        family_seq_chirho: input_chirho.family_seq_chirho,
        family_line_digest_chirho: prefixed_hash_chirho(
            HEAD_TRANSITION_FAMILY_LINE_DIGEST_PREFIX_CHIRHO,
            canonical_signed_family_line_chirho,
        ),
        branch_chirho: input_chirho.branch_chirho.to_string(),
        previous_chirho: input_chirho.previous_chirho.clone(),
        next_chirho: input_chirho.next_chirho.clone(),
        reason_chirho: input_chirho.reason_chirho.to_string(),
        writer_fence_group_digest_chirho: consistency_group_digest_chirho(
            input_chirho.prepared_group_chirho,
        )?,
        prepared_writer_fence_epoch_chirho: input_chirho.prepared_epoch_chirho,
        prepared_root_binding_chirho,
        at_ms_chirho: input_chirho.at_ms_chirho,
    })
}

/// Complete or repair one caller-verified transition while the writer and append locks are held.
pub fn complete_head_transition_unlocked_chirho(
    root_chirho: &Path,
    prepared_chirho: &PreparedHeadTransitionChirho,
    applier_fence_chirho: &WriterFenceTokenChirho,
) -> Result<HeadTransitionRecoveryOutcomeChirho> {
    preflight_head_transition_commit_chirho(root_chirho, prepared_chirho, applier_fence_chirho)?;

    recover_reflog_tail_chirho(root_chirho)?;
    if verified_receipt_for_transition_chirho(root_chirho, prepared_chirho)?.is_some() {
        return Ok(HeadTransitionRecoveryOutcomeChirho::AlreadyAppliedChirho);
    }

    let receipt_chirho = signed_receipt_chirho(root_chirho, prepared_chirho, applier_fence_chirho)?;
    let outcome_chirho =
        refs_chirho::commit_head_with_transition_receipt_chirho(root_chirho, &receipt_chirho)?;
    recover_reflog_tail_chirho(root_chirho)?;
    let recorded_chirho = verified_receipt_for_transition_chirho(root_chirho, prepared_chirho)?
        .ok_or_else(|| anyhow::anyhow!("head transition receipt missing after ref completion"))?;
    if recorded_chirho != receipt_chirho {
        bail!("head transition recorded receipt differs from the applied receipt");
    }
    match outcome_chirho {
        HeadTransitionCommitOutcomeChirho::AppliedChirho => {
            Ok(HeadTransitionRecoveryOutcomeChirho::AppliedChirho)
        }
        HeadTransitionCommitOutcomeChirho::RepairedReflogChirho => {
            Ok(HeadTransitionRecoveryOutcomeChirho::RepairedReflogChirho)
        }
        HeadTransitionCommitOutcomeChirho::AlreadyRecordedChirho => {
            Ok(HeadTransitionRecoveryOutcomeChirho::AlreadyAppliedChirho)
        }
    }
}

/// Check every prepared-fence binding before a family row, ref, or receipt may be written.
pub fn preflight_head_transition_commit_chirho(
    root_chirho: &Path,
    prepared_chirho: &PreparedHeadTransitionChirho,
    applier_fence_chirho: &WriterFenceTokenChirho,
) -> Result<()> {
    preflight_transition_bindings_chirho(
        root_chirho,
        prepared_chirho.prepared_root_binding_chirho.as_ref(),
        &prepared_chirho.writer_fence_group_digest_chirho,
        prepared_chirho.prepared_writer_fence_epoch_chirho,
        applier_fence_chirho,
    )
}

pub(crate) fn preflight_prepared_fence_commit_chirho(
    root_chirho: &Path,
    prepared_chirho: &PreparedFenceLowerBoundChirho,
    applier_fence_chirho: &WriterFenceTokenChirho,
) -> Result<()> {
    preflight_transition_bindings_chirho(
        root_chirho,
        Some(prepared_chirho),
        &consistency_group_digest_chirho(prepared_chirho.group_chirho())?,
        prepared_chirho.epoch_chirho(),
        applier_fence_chirho,
    )
}

fn preflight_transition_bindings_chirho(
    root_chirho: &Path,
    prepared_root_binding_chirho: Option<&PreparedFenceLowerBoundChirho>,
    prepared_group_digest_chirho: &str,
    prepared_epoch_chirho: u64,
    applier_fence_chirho: &WriterFenceTokenChirho,
) -> Result<()> {
    if let Some(prepared_root_binding_chirho) = prepared_root_binding_chirho {
        let root_matches_chirho = prepared_root_binding_chirho
            .root_identity_matches_chirho(root_chirho)
            .context("HeadTransitionWrongRootChirho: inspect COMMIT root binding")?;
        if !root_matches_chirho {
            bail!("HeadTransitionWrongRootChirho: COMMIT root differs from PREPARE root");
        }
    }
    let applier_group_digest_chirho =
        consistency_group_digest_chirho(&applier_fence_chirho.group_chirho)?;
    if applier_group_digest_chirho != prepared_group_digest_chirho {
        bail!("HeadTransitionWrongGroupChirho: COMMIT fence belongs to another group");
    }
    if applier_fence_chirho.epoch_chirho < prepared_epoch_chirho {
        bail!("HeadTransitionPreparedFenceEpochRegressionChirho: COMMIT fence predates PREPARE");
    }
    verify_writer_fence_for_root_chirho(root_chirho, applier_fence_chirho)
        .map_err(anyhow::Error::new)
        .context("HeadTransitionApplierFenceNotCurrentChirho")?;
    Ok(())
}

/// Issue a fresh current fence and recover one caller-verified prepared transition.
pub fn recover_head_transition_chirho(
    root_chirho: &Path,
    prepared_chirho: &PreparedHeadTransitionChirho,
) -> Result<HeadTransitionRecoveryOutcomeChirho> {
    with_head_transition_scope_chirho(root_chirho, |applier_fence_chirho| {
        complete_head_transition_unlocked_chirho(root_chirho, prepared_chirho, applier_fence_chirho)
    })
}

/// Verify whether one caller-verified transition has an authoritative Applied receipt.
///
/// This read-only witness never repairs a torn reflog tail, signs, or writes. Callers that need
/// recovery must enter the separately reviewed writer-fenced recovery path.
pub fn verified_head_transition_receipt_chirho(
    root_chirho: &Path,
    prepared_chirho: &PreparedHeadTransitionChirho,
) -> Result<bool> {
    Ok(verified_receipt_for_transition_chirho(root_chirho, prepared_chirho)?.is_some())
}

/// Classify caller-verified prepared transitions while the writer and append locks are held.
pub fn pending_head_transition_index_unlocked_chirho(
    root_chirho: &Path,
    current_head_chirho: &Option<HashChirho>,
    prepared_chirho: &[PreparedHeadTransitionChirho],
) -> Result<Option<usize>> {
    recover_reflog_tail_chirho(root_chirho)?;
    let mut pending_index_chirho = None;
    for (index_chirho, candidate_chirho) in prepared_chirho.iter().enumerate() {
        if verified_receipt_for_transition_chirho(root_chirho, candidate_chirho)?.is_some() {
            continue;
        }
        if current_head_chirho != &candidate_chirho.previous_chirho
            && current_head_chirho != &Some(candidate_chirho.next_chirho.clone())
        {
            bail!(
                "unapplied head transition '{}' diverges from the current head",
                candidate_chirho.transition_id_chirho
            );
        }
        if pending_index_chirho.replace(index_chirho).is_some() {
            bail!("multiple unapplied head transitions match one current head");
        }
    }
    Ok(pending_index_chirho)
}

pub fn head_transition_receipt_core_digest_chirho(
    receipt_chirho: &ReflogEntryChirho,
) -> Result<String> {
    validate_receipt_shape_chirho(receipt_chirho)?;
    #[derive(Serialize)]
    struct ReceiptCoreChirho<'a> {
        schema_chirho: &'a str,
        transition_id_chirho: &'a str,
        family_log_chirho: &'a str,
        family_seq_chirho: u64,
        family_line_digest_chirho: &'a str,
        branch_chirho: &'a str,
        from_chirho: &'a Option<HashChirho>,
        to_chirho: &'a HashChirho,
        reason_chirho: &'a str,
        at_ms_chirho: u64,
        writer_fence_group_digest_chirho: &'a str,
        prepared_writer_fence_epoch_chirho: u64,
        key_id_chirho: &'a str,
    }
    let bytes_chirho = serde_json::to_vec(&ReceiptCoreChirho {
        schema_chirho: &receipt_chirho.schema_chirho,
        transition_id_chirho: &receipt_chirho.transition_id_chirho,
        family_log_chirho: &receipt_chirho.family_log_chirho,
        family_seq_chirho: receipt_chirho.family_seq_chirho.unwrap(),
        family_line_digest_chirho: &receipt_chirho.family_line_digest_chirho,
        branch_chirho: &receipt_chirho.branch_chirho,
        from_chirho: &receipt_chirho.from_chirho,
        to_chirho: &receipt_chirho.to_chirho,
        reason_chirho: &receipt_chirho.reason_chirho,
        at_ms_chirho: receipt_chirho.at_ms_chirho,
        writer_fence_group_digest_chirho: &receipt_chirho.writer_fence_group_digest_chirho,
        prepared_writer_fence_epoch_chirho: receipt_chirho
            .prepared_writer_fence_epoch_chirho
            .unwrap(),
        key_id_chirho: &receipt_chirho.key_id_chirho,
    })?;
    Ok(prefixed_hash_chirho(
        HEAD_TRANSITION_RECEIPT_CORE_DIGEST_PREFIX_CHIRHO,
        &bytes_chirho,
    ))
}

fn signed_receipt_chirho(
    root_chirho: &Path,
    prepared_chirho: &PreparedHeadTransitionChirho,
    applier_fence_chirho: &WriterFenceTokenChirho,
) -> Result<ReflogEntryChirho> {
    let key_id_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    let mut receipt_chirho = ReflogEntryChirho {
        branch_chirho: prepared_chirho.branch_chirho.clone(),
        from_chirho: prepared_chirho.previous_chirho.clone(),
        to_chirho: prepared_chirho.next_chirho.clone(),
        reason_chirho: prepared_chirho.reason_chirho.clone(),
        at_ms_chirho: prepared_chirho.at_ms_chirho,
        schema_chirho: HEAD_TRANSITION_RECEIPT_SCHEMA_CHIRHO.to_string(),
        transition_id_chirho: prepared_chirho.transition_id_chirho.clone(),
        family_log_chirho: prepared_chirho.family_log_chirho.clone(),
        family_seq_chirho: Some(prepared_chirho.family_seq_chirho),
        family_line_digest_chirho: prepared_chirho.family_line_digest_chirho.clone(),
        writer_fence_group_digest_chirho: prepared_chirho.writer_fence_group_digest_chirho.clone(),
        prepared_writer_fence_epoch_chirho: Some(
            prepared_chirho.prepared_writer_fence_epoch_chirho,
        ),
        applied_writer_fence_epoch_chirho: Some(applier_fence_chirho.epoch_chirho),
        key_id_chirho,
        sig_chirho: String::new(),
    };
    let message_chirho = unsigned_receipt_message_chirho(&receipt_chirho)?;
    receipt_chirho.sig_chirho =
        signer_chirho::sign_message_with_existing_key_chirho(root_chirho, &message_chirho)?;
    Ok(receipt_chirho)
}

fn verified_receipt_for_transition_chirho(
    root_chirho: &Path,
    prepared_chirho: &PreparedHeadTransitionChirho,
) -> Result<Option<ReflogEntryChirho>> {
    let matching_chirho = refs_chirho::reflog_chirho(root_chirho)?
        .into_iter()
        .filter(|receipt_chirho| {
            receipt_chirho.transition_id_chirho == prepared_chirho.transition_id_chirho
                || (receipt_chirho.family_log_chirho == prepared_chirho.family_log_chirho
                    && receipt_chirho.family_seq_chirho == Some(prepared_chirho.family_seq_chirho)
                    && receipt_chirho.family_line_digest_chirho
                        == prepared_chirho.family_line_digest_chirho)
        })
        .collect::<Vec<_>>();
    match matching_chirho.as_slice() {
        [] => Ok(None),
        [receipt_chirho] => {
            verify_receipt_against_prepared_chirho(root_chirho, receipt_chirho, prepared_chirho)?;
            Ok(Some(receipt_chirho.clone()))
        }
        _ => bail!(
            "head transition '{}' has duplicate reflog receipts",
            prepared_chirho.transition_id_chirho
        ),
    }
}

fn verify_receipt_against_prepared_chirho(
    root_chirho: &Path,
    receipt_chirho: &ReflogEntryChirho,
    prepared_chirho: &PreparedHeadTransitionChirho,
) -> Result<()> {
    validate_receipt_shape_chirho(receipt_chirho)?;
    if receipt_chirho.transition_id_chirho != prepared_chirho.transition_id_chirho
        || receipt_chirho.family_log_chirho != prepared_chirho.family_log_chirho
        || receipt_chirho.family_seq_chirho != Some(prepared_chirho.family_seq_chirho)
        || receipt_chirho.family_line_digest_chirho != prepared_chirho.family_line_digest_chirho
        || receipt_chirho.branch_chirho != prepared_chirho.branch_chirho
        || receipt_chirho.from_chirho != prepared_chirho.previous_chirho
        || receipt_chirho.to_chirho != prepared_chirho.next_chirho
        || receipt_chirho.reason_chirho != prepared_chirho.reason_chirho
        || receipt_chirho.at_ms_chirho != prepared_chirho.at_ms_chirho
        || receipt_chirho.writer_fence_group_digest_chirho
            != prepared_chirho.writer_fence_group_digest_chirho
        || receipt_chirho.prepared_writer_fence_epoch_chirho
            != Some(prepared_chirho.prepared_writer_fence_epoch_chirho)
    {
        bail!("head transition receipt does not match the caller-verified prepared transition");
    }
    let existing_key_id_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    if receipt_chirho.key_id_chirho != existing_key_id_chirho {
        bail!("head transition receipt key is not the root-pinned existing key");
    }
    let message_chirho = unsigned_receipt_message_chirho(receipt_chirho)?;
    if !signer_chirho::verify_with_pubkey_chirho(
        &existing_key_id_chirho,
        &message_chirho,
        &receipt_chirho.sig_chirho,
    )? {
        bail!("head transition receipt signature invalid");
    }
    Ok(())
}

fn validate_receipt_shape_chirho(receipt_chirho: &ReflogEntryChirho) -> Result<()> {
    if receipt_chirho.schema_chirho != HEAD_TRANSITION_RECEIPT_SCHEMA_CHIRHO {
        bail!("unsupported head transition receipt schema");
    }
    if !receipt_chirho
        .transition_id_chirho
        .starts_with(HEAD_TRANSITION_ID_PREFIX_CHIRHO)
    {
        bail!("head transition receipt id has the wrong domain prefix");
    }
    validate_family_log_chirho(&receipt_chirho.family_log_chirho)?;
    if receipt_chirho.family_seq_chirho.is_none()
        || !receipt_chirho
            .family_line_digest_chirho
            .starts_with(HEAD_TRANSITION_FAMILY_LINE_DIGEST_PREFIX_CHIRHO)
        || receipt_chirho.writer_fence_group_digest_chirho.is_empty()
        || receipt_chirho.prepared_writer_fence_epoch_chirho.is_none()
        || receipt_chirho.applied_writer_fence_epoch_chirho.is_none()
        || receipt_chirho.key_id_chirho.is_empty()
        || receipt_chirho.sig_chirho.is_empty()
    {
        bail!("head transition receipt is incomplete");
    }
    let prepared_epoch_chirho = receipt_chirho.prepared_writer_fence_epoch_chirho.unwrap();
    let applied_epoch_chirho = receipt_chirho.applied_writer_fence_epoch_chirho.unwrap();
    if prepared_epoch_chirho == 0 || applied_epoch_chirho < prepared_epoch_chirho {
        bail!("head transition receipt fence epochs are invalid");
    }
    Ok(())
}

fn unsigned_receipt_message_chirho(receipt_chirho: &ReflogEntryChirho) -> Result<Vec<u8>> {
    let mut unsigned_chirho = receipt_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

fn recover_reflog_tail_chirho(root_chirho: &Path) -> Result<()> {
    seqlog_chirho::recover_jsonl_len_unlocked_chirho(&refs_chirho::reflog_path_chirho(
        root_chirho,
    ))?;
    Ok(())
}

fn validate_identity_parts_chirho(
    input_chirho: &HeadTransitionIdentityPartsChirho<'_>,
) -> Result<()> {
    validate_family_log_chirho(input_chirho.family_log_chirho)?;
    if input_chirho.branch_chirho.trim().is_empty()
        || input_chirho.reason_chirho.trim().is_empty()
        || input_chirho.operation_bytes_chirho.is_empty()
        || input_chirho.prepared_epoch_chirho == 0
    {
        bail!("head transition identity input is incomplete");
    }
    if input_chirho.previous_chirho.as_ref() == Some(input_chirho.next_chirho) {
        bail!("head transition must move to a different hash");
    }
    Ok(())
}

fn validate_family_log_chirho(family_log_chirho: &str) -> Result<()> {
    let components_chirho = Path::new(family_log_chirho)
        .components()
        .collect::<Vec<_>>();
    if components_chirho.len() != 1
        || !matches!(components_chirho[0], Component::Normal(_))
        || !family_log_chirho.ends_with("-chirho.jsonl")
    {
        bail!("head transition family log must be a basename Chirho JSONL file");
    }
    Ok(())
}

fn prefixed_hash_chirho(prefix_chirho: &str, bytes_chirho: &[u8]) -> String {
    format!("{prefix_chirho}{}", blake3::hash(bytes_chirho).to_hex())
}

fn hex_bytes_chirho(bytes_chirho: &[u8]) -> String {
    bytes_chirho
        .iter()
        .map(|byte_chirho| format!("{byte_chirho:02x}"))
        .collect()
}

#[cfg(test)]
#[path = "head_transition_chirho/tests_chirho.rs"]
mod tests_chirho;
