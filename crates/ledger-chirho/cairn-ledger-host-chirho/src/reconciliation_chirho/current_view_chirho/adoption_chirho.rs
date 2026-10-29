// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Complete held winner-view verification evidence for later GD7 adoption.
//!
//! The total page walk happens before freshness is minted. The final verifier then consumes one
//! opaque locally issued challenge, rechecks the real elector on both sides of the signed response,
//! and performs only O(1) work. These proofs cannot move refs, compensate, or re-enable writes.
//! They do not stop a same-term winner append after signing; a later adoption sink still needs a
//! winner-side handoff barrier retained through commit.

use super::bundle_chirho::parse_verified_inline_bundle_page_chirho;
use super::{
    gd7_held_view_transfer_received_page_path_chirho,
    parse_canonical_gd7_winner_current_view_challenge_chirho,
    validate_challenge_against_group_chirho,
    verify_inline_gd7_winner_current_view_inspection_chirho, Gd7HeldViewTransferIdentityChirho,
    Gd7HeldViewTransferPhaseChirho, Gd7HeldViewTransferStoreChirho,
    Gd7HeldViewTransferStoreRefusalChirho, Gd7ReconciliationSignerPortChirho,
    Gd7ReconciliationVerifierPortChirho, Gd7WinnerCurrentViewInspectionChirho,
    Gd7WinnerCurrentViewRefusalChirho, Gd7WinnerViewBundleRootChirho,
    IssuedGd7WinnerCurrentViewChallengeChirho, MAX_GD7_WINNER_VIEW_BUNDLE_PAGE_BYTES_CHIRHO,
};
use cairn_ledger_log_chirho::ports_chirho::{LedgerStoragePortChirho, StoragePathChirho};
use cairn_ledger_read_model_chirho::AccountNetProjectionRowChirho;
use cairn_writer_elector_chirho::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::error::Error;
use std::fmt;

/// Read-only proof that one exact completed held transfer contains every and only the pages named
/// by its winner-signed bundle root.
///
/// The type is intentionally not serializable and its fields are private. It is evidence, not
/// authority: the fresh verifier below can bind one point-in-time winner statement to this chain,
/// but only a later actor-owned handoff barrier may authorize adoption.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedGd7HeldWinnerViewChainChirho {
    transfer_identity_digest_chirho: String,
    transfer_checkpoint_ref_chirho: String,
    consistency_group_digest_chirho: String,
    winner_node_chirho: String,
    held_node_chirho: String,
    winner_term_chirho: u64,
    bundle_root_object_digest_chirho: String,
    bundle_root_chirho: Gd7WinnerViewBundleRootChirho,
    received_page_count_chirho: u64,
    received_row_count_chirho: u64,
}

impl VerifiedGd7HeldWinnerViewChainChirho {
    pub fn transfer_identity_digest_chirho(&self) -> &str {
        &self.transfer_identity_digest_chirho
    }

    pub fn transfer_checkpoint_ref_chirho(&self) -> &str {
        &self.transfer_checkpoint_ref_chirho
    }

    pub fn bundle_root_object_digest_chirho(&self) -> &str {
        &self.bundle_root_object_digest_chirho
    }

    pub fn received_page_count_chirho(&self) -> u64 {
        self.received_page_count_chirho
    }

    pub fn received_row_count_chirho(&self) -> u64 {
        self.received_row_count_chirho
    }

    pub(super) fn consistency_group_digest_chirho(&self) -> &str {
        &self.consistency_group_digest_chirho
    }

    pub(super) fn winner_node_chirho(&self) -> &str {
        &self.winner_node_chirho
    }

    pub(super) fn held_node_chirho(&self) -> &str {
        &self.held_node_chirho
    }

    pub(super) fn winner_term_chirho(&self) -> u64 {
        self.winner_term_chirho
    }

    pub(super) fn bundle_root_chirho(&self) -> &Gd7WinnerViewBundleRootChirho {
        &self.bundle_root_chirho
    }
}

/// Opaque evidence that one point-in-time winner statement matches a completely received chain.
///
/// This value has no public constructor and grants no mutation method. It is deliberately not an
/// adoption prerequisite: callers supply the verifier and elector ports, and a same-term append can
/// occur after the winner signs. A future sink must instead consume a crate-private composite
/// minted inside the held actor while a winner-side handoff barrier remains active.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedGd7HeldWinnerViewFreshnessEvidenceChirho {
    verified_chain_chirho: VerifiedGd7HeldWinnerViewChainChirho,
    fresh_evidence_object_digest_chirho: String,
    winner_process_generation_chirho: u64,
}

impl VerifiedGd7HeldWinnerViewFreshnessEvidenceChirho {
    pub fn transfer_checkpoint_ref_chirho(&self) -> &str {
        self.verified_chain_chirho.transfer_checkpoint_ref_chirho()
    }

    pub fn bundle_root_object_digest_chirho(&self) -> &str {
        self.verified_chain_chirho
            .bundle_root_object_digest_chirho()
    }

    pub fn fresh_evidence_object_digest_chirho(&self) -> &str {
        &self.fresh_evidence_object_digest_chirho
    }

    pub fn winner_process_generation_chirho(&self) -> u64 {
        self.winner_process_generation_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7HeldWinnerViewVerificationRefusalChirho {
    TransferStoreChirho(Gd7HeldViewTransferStoreRefusalChirho),
    CurrentViewChirho(Gd7WinnerCurrentViewRefusalChirho),
    IncompleteTransferChirho,
    StaleTransferChirho,
    WinnerViewChangedChirho,
    InvalidReceivedChainChirho,
    MissingReceivedPageChirho,
    StorageChirho,
}

impl fmt::Display for Gd7HeldWinnerViewVerificationRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransferStoreChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 held transfer refused: {error_chirho}"
                )
            }
            Self::CurrentViewChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 fresh winner view refused: {error_chirho}"
                )
            }
            Self::IncompleteTransferChirho => {
                formatter_chirho.write_str("GD7 held winner-view transfer is not complete")
            }
            Self::StaleTransferChirho => {
                formatter_chirho.write_str("GD7 held winner-view transfer checkpoint changed")
            }
            Self::WinnerViewChangedChirho => formatter_chirho
                .write_str("GD7 fresh winner view differs from the completely received view"),
            Self::InvalidReceivedChainChirho => {
                formatter_chirho.write_str("GD7 held winner-view page chain is invalid")
            }
            Self::MissingReceivedPageChirho => {
                formatter_chirho.write_str("GD7 held winner-view page is missing")
            }
            Self::StorageChirho => {
                formatter_chirho.write_str("GD7 held winner-view storage read failed")
            }
        }
    }
}

impl Error for Gd7HeldWinnerViewVerificationRefusalChirho {}

impl From<Gd7HeldViewTransferStoreRefusalChirho> for Gd7HeldWinnerViewVerificationRefusalChirho {
    fn from(error_chirho: Gd7HeldViewTransferStoreRefusalChirho) -> Self {
        Self::TransferStoreChirho(error_chirho)
    }
}

impl From<Gd7WinnerCurrentViewRefusalChirho> for Gd7HeldWinnerViewVerificationRefusalChirho {
    fn from(error_chirho: Gd7WinnerCurrentViewRefusalChirho) -> Self {
        Self::CurrentViewChirho(error_chirho)
    }
}

/// Reverify one exact completed transfer and its entire content-addressed page chain.
///
/// Work is O(received pages + rows), memory is O(page), and every read is a point lookup named by
/// the signed root or the preceding verified page. No directory, tenant, account, or history scan
/// occurs. The fixed head is reloaded after traversal and must remain byte-equal.
pub fn verify_complete_gd7_held_winner_view_chain_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    winner_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    identity_chirho: Gd7HeldViewTransferIdentityChirho,
    expected_checkpoint_ref_chirho: &str,
) -> Result<VerifiedGd7HeldWinnerViewChainChirho, Gd7HeldWinnerViewVerificationRefusalChirho> {
    verify_complete_gd7_held_winner_view_chain_with_rows_chirho(
        storage_chirho,
        held_signer_chirho,
        winner_verifier_chirho,
        identity_chirho,
        expected_checkpoint_ref_chirho,
        |_row_chirho| {},
    )
}

/// Reverify one complete held view and visit its canonical rows in ascending account order.
///
/// The visitor is evidence-only. The complete held-signed checkpoint and every content-addressed
/// page are still rechecked by the same implementation used by the public chain verifier.
pub(super) fn verify_complete_gd7_held_winner_view_chain_with_rows_chirho<VisitChirho>(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    winner_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    identity_chirho: Gd7HeldViewTransferIdentityChirho,
    expected_checkpoint_ref_chirho: &str,
    mut visit_chirho: VisitChirho,
) -> Result<VerifiedGd7HeldWinnerViewChainChirho, Gd7HeldWinnerViewVerificationRefusalChirho>
where
    VisitChirho: FnMut(&AccountNetProjectionRowChirho),
{
    let store_chirho = Gd7HeldViewTransferStoreChirho::new_chirho(
        storage_chirho,
        held_signer_chirho,
        winner_verifier_chirho,
        identity_chirho.clone(),
    )?;
    let active_chirho = store_chirho
        .load_active_chirho()?
        .ok_or(Gd7HeldWinnerViewVerificationRefusalChirho::IncompleteTransferChirho)?;
    if active_chirho.checkpoint_ref_chirho != expected_checkpoint_ref_chirho {
        return Err(Gd7HeldWinnerViewVerificationRefusalChirho::StaleTransferChirho);
    }
    let checkpoint_chirho = &active_chirho.checkpoint_chirho;
    if checkpoint_chirho.phase_chirho != Gd7HeldViewTransferPhaseChirho::CompleteChirho {
        return Err(Gd7HeldWinnerViewVerificationRefusalChirho::IncompleteTransferChirho);
    }
    let challenge_chirho = parse_canonical_gd7_winner_current_view_challenge_chirho(
        checkpoint_chirho
            .canonical_challenge_chirho
            .as_deref()
            .ok_or(Gd7HeldWinnerViewVerificationRefusalChirho::InvalidReceivedChainChirho)?
            .as_bytes(),
    )?;
    if challenge_chirho.consistency_group_digest_chirho()
        != identity_chirho.consistency_group_digest_chirho
        || challenge_chirho.expected_winner_node_chirho() != identity_chirho.winner_node_chirho
        || challenge_chirho.held_node_chirho() != identity_chirho.held_node_chirho
        || challenge_chirho.transfer_identity_digest_chirho()
            != store_chirho.identity_digest_chirho()
        || challenge_chirho.raft_term_chirho() != identity_chirho.winner_term_chirho
    {
        return Err(Gd7HeldWinnerViewVerificationRefusalChirho::InvalidReceivedChainChirho);
    }
    let inspection_chirho = checkpoint_chirho
        .inspection_chirho
        .as_ref()
        .ok_or(Gd7HeldWinnerViewVerificationRefusalChirho::InvalidReceivedChainChirho)?;
    verify_inline_gd7_winner_current_view_inspection_chirho(
        &challenge_chirho,
        winner_verifier_chirho,
        inspection_chirho,
    )?;
    let root_chirho = &inspection_chirho.bundle_root_chirho;
    if checkpoint_chirho.staged_bundle_root_ref_chirho.as_deref()
        != Some(inspection_chirho.bundle_root_object_digest_chirho.as_str())
        || checkpoint_chirho.staged_page_count_chirho != Some(root_chirho.page_count_chirho)
        || checkpoint_chirho.staged_row_count_chirho != Some(root_chirho.row_count_chirho)
        || checkpoint_chirho.received_page_count_chirho != root_chirho.page_count_chirho
        || checkpoint_chirho.received_row_count_chirho != root_chirho.row_count_chirho
    {
        return Err(Gd7HeldWinnerViewVerificationRefusalChirho::InvalidReceivedChainChirho);
    }
    verify_received_page_chain_chirho(
        storage_chirho,
        checkpoint_chirho,
        root_chirho,
        &mut visit_chirho,
    )?;
    let reloaded_chirho = store_chirho
        .load_active_chirho()?
        .ok_or(Gd7HeldWinnerViewVerificationRefusalChirho::StaleTransferChirho)?;
    if reloaded_chirho != active_chirho {
        return Err(Gd7HeldWinnerViewVerificationRefusalChirho::StaleTransferChirho);
    }
    Ok(VerifiedGd7HeldWinnerViewChainChirho {
        transfer_identity_digest_chirho: store_chirho.identity_digest_chirho().to_owned(),
        transfer_checkpoint_ref_chirho: active_chirho.checkpoint_ref_chirho,
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho,
        winner_node_chirho: identity_chirho.winner_node_chirho,
        held_node_chirho: identity_chirho.held_node_chirho,
        winner_term_chirho: identity_chirho.winner_term_chirho,
        bundle_root_object_digest_chirho: inspection_chirho
            .bundle_root_object_digest_chirho
            .clone(),
        bundle_root_chirho: root_chirho.clone(),
        received_page_count_chirho: checkpoint_chirho.received_page_count_chirho,
        received_row_count_chirho: checkpoint_chirho.received_row_count_chirho,
    })
}

/// Consume one newly issued challenge after the total page/plan walks and bind its point-in-time
/// winner statement to the already verified complete received chain.
///
/// This is O(1) work. An append completed before the statement changes the winner root/cut and
/// refuses; a leadership change on either side of signature verification also refuses. An append
/// after signing remains possible, so the returned evidence is not ref-movement authority.
pub fn verify_fresh_gd7_held_winner_view_evidence_chirho<
    ElectorChirho: WriterElectorChirho + ?Sized,
>(
    verified_chain_chirho: VerifiedGd7HeldWinnerViewChainChirho,
    winner_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    elector_chirho: &ElectorChirho,
    group_chirho: &ConsistencyGroupIdChirho,
    expected_winner_chirho: &NodeIdChirho,
    issued_challenge_chirho: IssuedGd7WinnerCurrentViewChallengeChirho,
    fresh_inspection_chirho: &Gd7WinnerCurrentViewInspectionChirho,
) -> Result<
    VerifiedGd7HeldWinnerViewFreshnessEvidenceChirho,
    Gd7HeldWinnerViewVerificationRefusalChirho,
> {
    let challenge_chirho = issued_challenge_chirho.into_challenge_chirho();
    validate_challenge_against_group_chirho(
        &challenge_chirho,
        group_chirho,
        expected_winner_chirho,
    )?;
    if challenge_chirho.consistency_group_digest_chirho()
        != verified_chain_chirho.consistency_group_digest_chirho
        || challenge_chirho.expected_winner_node_chirho()
            != verified_chain_chirho.winner_node_chirho
        || challenge_chirho.held_node_chirho() != verified_chain_chirho.held_node_chirho
        || challenge_chirho.transfer_identity_digest_chirho()
            != verified_chain_chirho.transfer_identity_digest_chirho
        || challenge_chirho.raft_term_chirho() != verified_chain_chirho.winner_term_chirho
        || winner_verifier_chirho.key_id_chirho() != verified_chain_chirho.winner_node_chirho
    {
        return Err(Gd7HeldWinnerViewVerificationRefusalChirho::WinnerViewChangedChirho);
    }
    let before_chirho = super::observe_expected_winner_chirho(
        elector_chirho,
        group_chirho,
        expected_winner_chirho,
    )?;
    if before_chirho.term_chirho != challenge_chirho.raft_term_chirho() {
        return Err(Gd7HeldWinnerViewVerificationRefusalChirho::WinnerViewChangedChirho);
    }
    verify_inline_gd7_winner_current_view_inspection_chirho(
        &challenge_chirho,
        winner_verifier_chirho,
        fresh_inspection_chirho,
    )?;
    if fresh_inspection_chirho.bundle_root_object_digest_chirho
        != verified_chain_chirho.bundle_root_object_digest_chirho
        || fresh_inspection_chirho.bundle_root_chirho != verified_chain_chirho.bundle_root_chirho
    {
        return Err(Gd7HeldWinnerViewVerificationRefusalChirho::WinnerViewChangedChirho);
    }
    let after_chirho =
        super::observe_expected_winner_chirho(elector_chirho, group_chirho, expected_winner_chirho)
            .map_err(|_error_chirho| {
                Gd7HeldWinnerViewVerificationRefusalChirho::WinnerViewChangedChirho
            })?;
    if before_chirho.leader_id_chirho != after_chirho.leader_id_chirho
        || before_chirho.term_chirho != after_chirho.term_chirho
    {
        return Err(Gd7HeldWinnerViewVerificationRefusalChirho::WinnerViewChangedChirho);
    }
    Ok(VerifiedGd7HeldWinnerViewFreshnessEvidenceChirho {
        verified_chain_chirho,
        fresh_evidence_object_digest_chirho: fresh_inspection_chirho
            .evidence_object_digest_chirho
            .clone(),
        winner_process_generation_chirho: fresh_inspection_chirho
            .evidence_chirho
            .winner_process_generation_chirho,
    })
}

fn verify_received_page_chain_chirho<VisitChirho>(
    storage_chirho: &dyn LedgerStoragePortChirho,
    checkpoint_chirho: &super::Gd7HeldViewTransferCheckpointChirho,
    root_chirho: &Gd7WinnerViewBundleRootChirho,
    visit_chirho: &mut VisitChirho,
) -> Result<(), Gd7HeldWinnerViewVerificationRefusalChirho>
where
    VisitChirho: FnMut(&AccountNetProjectionRowChirho),
{
    if root_chirho.page_count_chirho == 0 {
        if root_chirho.lowest_page_ref_chirho.is_some()
            || checkpoint_chirho.latest_received_page_ref_chirho.is_some()
            || root_chirho.row_count_chirho != 0
        {
            return Err(Gd7HeldWinnerViewVerificationRefusalChirho::InvalidReceivedChainChirho);
        }
        return Ok(());
    }
    let mut remaining_page_count_chirho = root_chirho.page_count_chirho;
    let mut remaining_row_count_chirho = root_chirho.row_count_chirho;
    let mut current_page_ref_chirho = root_chirho.lowest_page_ref_chirho.clone();
    let mut lower_page_last_account_chirho = None;
    let mut final_highest_page_ref_chirho = None;

    while remaining_page_count_chirho > 0 {
        let expected_page_index_chirho = remaining_page_count_chirho
            .checked_sub(1)
            .ok_or(Gd7HeldWinnerViewVerificationRefusalChirho::InvalidReceivedChainChirho)?;
        let page_ref_chirho = current_page_ref_chirho
            .as_deref()
            .ok_or(Gd7HeldWinnerViewVerificationRefusalChirho::InvalidReceivedChainChirho)?;
        let page_path_chirho = gd7_held_view_transfer_received_page_path_chirho(page_ref_chirho)?;
        let page_bytes_chirho = read_received_page_chirho(storage_chirho, &page_path_chirho)?
            .ok_or(Gd7HeldWinnerViewVerificationRefusalChirho::MissingReceivedPageChirho)?;
        let verified_page_chirho = parse_verified_inline_bundle_page_chirho(&page_bytes_chirho)?;
        let page_chirho = &verified_page_chirho.page_chirho;
        let local_row_count_chirho = u64::try_from(page_chirho.rows_chirho.len())
            .map_err(|_| Gd7HeldWinnerViewVerificationRefusalChirho::InvalidReceivedChainChirho)?;
        if verified_page_chirho.object_digest_chirho != page_ref_chirho
            || page_chirho.page_index_chirho != expected_page_index_chirho
            || page_chirho.consistency_group_digest_chirho
                != root_chirho.consistency_group_digest_chirho
            || page_chirho.projection_fold_ref_chirho != root_chirho.projection_fold_ref_chirho
            || page_chirho.winner_journal_genesis_digest_chirho
                != root_chirho.winner_journal_genesis_digest_chirho
            || page_chirho.source_cut_chirho != root_chirho.source_cut_chirho
            || page_chirho.cumulative_page_count_chirho != remaining_page_count_chirho
            || page_chirho.cumulative_row_count_chirho != remaining_row_count_chirho
            || (remaining_page_count_chirho == root_chirho.page_count_chirho)
                != page_chirho.next_upper_exclusive_account_chirho.is_none()
        {
            return Err(Gd7HeldWinnerViewVerificationRefusalChirho::InvalidReceivedChainChirho);
        }
        if let Some(lower_page_last_account_chirho) = lower_page_last_account_chirho.as_ref() {
            let higher_page_first_account_chirho = &page_chirho
                .rows_chirho
                .first()
                .ok_or(Gd7HeldWinnerViewVerificationRefusalChirho::InvalidReceivedChainChirho)?
                .account_chirho;
            if lower_page_last_account_chirho >= higher_page_first_account_chirho {
                return Err(Gd7HeldWinnerViewVerificationRefusalChirho::InvalidReceivedChainChirho);
            }
        }
        lower_page_last_account_chirho = Some(
            page_chirho
                .rows_chirho
                .last()
                .ok_or(Gd7HeldWinnerViewVerificationRefusalChirho::InvalidReceivedChainChirho)?
                .account_chirho
                .clone(),
        );
        for row_chirho in &page_chirho.rows_chirho {
            visit_chirho(row_chirho);
        }
        remaining_page_count_chirho = expected_page_index_chirho;
        remaining_row_count_chirho = remaining_row_count_chirho
            .checked_sub(local_row_count_chirho)
            .ok_or(Gd7HeldWinnerViewVerificationRefusalChirho::InvalidReceivedChainChirho)?;
        current_page_ref_chirho = page_chirho.higher_page_ref_chirho.clone();
        final_highest_page_ref_chirho = Some(verified_page_chirho.object_digest_chirho);
    }
    if remaining_row_count_chirho != 0
        || current_page_ref_chirho.is_some()
        || checkpoint_chirho.latest_received_page_ref_chirho != final_highest_page_ref_chirho
    {
        return Err(Gd7HeldWinnerViewVerificationRefusalChirho::InvalidReceivedChainChirho);
    }
    Ok(())
}

fn read_received_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
) -> Result<Option<Vec<u8>>, Gd7HeldWinnerViewVerificationRefusalChirho> {
    let Some(length_chirho) = storage_chirho
        .object_len_chirho(path_chirho)
        .map_err(|_| Gd7HeldWinnerViewVerificationRefusalChirho::StorageChirho)?
    else {
        return Ok(None);
    };
    if length_chirho > MAX_GD7_WINNER_VIEW_BUNDLE_PAGE_BYTES_CHIRHO as u64 {
        return Err(Gd7HeldWinnerViewVerificationRefusalChirho::InvalidReceivedChainChirho);
    }
    let bytes_chirho = if length_chirho == 0 {
        Vec::new()
    } else {
        storage_chirho
            .read_exact_range_chirho(path_chirho, 0, length_chirho)
            .map_err(|_| Gd7HeldWinnerViewVerificationRefusalChirho::StorageChirho)?
    };
    if bytes_chirho.len() != length_chirho as usize
        || storage_chirho
            .object_len_chirho(path_chirho)
            .map_err(|_| Gd7HeldWinnerViewVerificationRefusalChirho::StorageChirho)?
            != Some(length_chirho)
    {
        return Err(Gd7HeldWinnerViewVerificationRefusalChirho::StorageChirho);
    }
    Ok(Some(bytes_chirho))
}
