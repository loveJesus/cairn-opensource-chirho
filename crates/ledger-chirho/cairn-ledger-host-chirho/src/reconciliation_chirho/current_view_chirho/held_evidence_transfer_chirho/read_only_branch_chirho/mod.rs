// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Held-local, restart-verifiable GD7 read-only branch evidence.
//!
//! "Install" in this module means publishing a held-signed head over immutable, fully verified
//! evidence objects. No live journal, elector, resident authority, served ref, or write path reads
//! this head. A later actor-owned adoption brick must separately authorize making a branch live.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

mod contract_chirho;
mod storage_chirho;

use super::super::winner_history_chirho::{
    verify_complete_gd7_winner_history_chain_with_records_chirho, Gd7WinnerHistoryIdentityChirho,
};
use super::{
    gd7_held_evidence_transfer_identity_digest_chirho, Gd7HeldEvidenceTransferIdentityChirho,
    Gd7HeldEvidenceTransferStoreChirho, VerifiedGd7AccountNetCompositionChirho,
};
use crate::reconciliation_chirho::{
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{
    ExpectedLedgerGenesisChirho, MAX_EXPECTED_GENESIS_LINE_BYTES_CHIRHO,
};
use cairn_ledger_log_chirho::losing_suffix_chirho::{
    LosingSuffixCoordinateChirho, LosingSuffixPageRequestChirho, LosingSuffixReaderChirho,
    VerifiedLosingJournalTailChirho, MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
    MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO,
};
use cairn_ledger_log_chirho::ports_chirho::{LedgerStoragePortChirho, StoragePathChirho};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::record_chirho::LedgerRecordChirho;
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_record_line_chirho, parse_canonical_ledger_journal_line_chirho,
    stored_line_digest_chirho, LedgerJournalLineChirho,
};
pub use contract_chirho::{
    ActiveGd7ReadOnlyBranchChirho, Gd7ReadOnlyBranchCheckpointChirho, Gd7ReadOnlyBranchHeadChirho,
    Gd7ReadOnlyBranchPrefixRootChirho, Gd7ReadOnlyBranchRefusalChirho,
    PreparedGd7ReadOnlyBranchChirho, VerifiedGd7ReadOnlyBranchChirho,
    GD7_READ_ONLY_BRANCH_CHECKPOINT_SCHEMA_V1_CHIRHO, GD7_READ_ONLY_BRANCH_HEAD_SCHEMA_V1_CHIRHO,
    GD7_READ_ONLY_BRANCH_PREFIX_ROOT_SCHEMA_V1_CHIRHO,
    MAX_GD7_READ_ONLY_BRANCH_CHECKPOINT_BYTES_CHIRHO, MAX_GD7_READ_ONLY_BRANCH_HEAD_BYTES_CHIRHO,
    MAX_GD7_READ_ONLY_BRANCH_PREFIX_PAGE_BYTES_CHIRHO,
    MAX_GD7_READ_ONLY_BRANCH_PREFIX_ROOT_BYTES_CHIRHO,
};
use contract_chirho::{
    Gd7ReadOnlyBranchPrefixPageChirho, Gd7ReadOnlyBranchPrefixRecordChirho,
    GD7_READ_ONLY_BRANCH_PREFIX_PAGE_SCHEMA_V1_CHIRHO,
};
use serde::Serialize;
use storage_chirho::{
    canonical_json_chirho, create_exact_chirho, digest_bytes_chirho, digest_path_chirho,
    is_lower_hex_digest_chirho, parse_canonical_chirho, read_bounded_chirho,
};

pub fn gd7_read_only_branch_prefix_page_path_chirho(
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7ReadOnlyBranchRefusalChirho> {
    digest_path_chirho("held-read-only-prefix-pages-chirho", object_digest_chirho)
}

pub fn gd7_read_only_branch_prefix_root_path_chirho(
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7ReadOnlyBranchRefusalChirho> {
    digest_path_chirho("held-read-only-prefix-roots-chirho", object_digest_chirho)
}

pub fn gd7_read_only_branch_checkpoint_path_chirho(
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7ReadOnlyBranchRefusalChirho> {
    digest_path_chirho(
        "held-read-only-branch-checkpoints-chirho",
        object_digest_chirho,
    )
}

pub fn gd7_read_only_branch_head_path_chirho(
    identity_chirho: &Gd7HeldEvidenceTransferIdentityChirho,
) -> Result<StoragePathChirho, Gd7ReadOnlyBranchRefusalChirho> {
    let digest_chirho = gd7_held_evidence_transfer_identity_digest_chirho(identity_chirho)
        .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::InvalidIdentityChirho)?;
    digest_path_chirho("held-read-only-branch-heads-chirho", &digest_chirho)
}

impl Gd7HeldEvidenceTransferStoreChirho<'_> {
    /// Stage all immutable prefix/root/checkpoint objects without publishing an installed head.
    ///
    /// `losing_genesis_chirho` is the canonical commitment already derived from the publicly
    /// verified resident identity and retained beside the frozen losing reader.
    ///
    /// Total work is O(common prefix), but each source read and persisted page stays within the
    /// existing 256-record / 4 MiB losing-reader bounds and memory remains O(page).
    pub fn prepare_read_only_branch_evidence_chirho(
        &self,
        losing_reader_chirho: &dyn LosingSuffixReaderChirho,
        losing_genesis_chirho: &ExpectedLedgerGenesisChirho,
    ) -> Result<PreparedGd7ReadOnlyBranchChirho, Gd7ReadOnlyBranchRefusalChirho> {
        self.require_held_branch_signer_chirho()?;
        let composition_chirho = self.verify_account_net_composition_chirho()?;
        self.require_exact_losing_genesis_chirho(losing_genesis_chirho)?;
        let losing_tail_chirho = losing_reader_chirho.revalidate_current_losing_tail_chirho()?;
        self.require_exact_losing_tail_chirho(&losing_tail_chirho)?;
        let prefix_root_chirho = self.stage_prefix_root_chirho(
            losing_reader_chirho,
            losing_genesis_chirho,
            &losing_tail_chirho,
        )?;
        let prefix_root_ref_chirho = persist_signed_prefix_root_chirho(
            self.storage_chirho,
            self.held_signer_chirho,
            prefix_root_chirho,
        )?;
        let (prefix_count_chirho, winner_count_chirho) = self.verify_branch_halves_chirho(
            &prefix_root_ref_chirho,
            composition_chirho.winner_history_root_ref_chirho(),
        )?;
        let canonical_record_count_chirho = prefix_count_chirho
            .checked_add(winner_count_chirho)
            .ok_or(Gd7ReadOnlyBranchRefusalChirho::ArithmeticOverflowChirho)?;
        if canonical_record_count_chirho
            != self
                .identity_chirho
                .reconciliation_identity_chirho
                .winner_journal_tail_chirho
                .seq_chirho
        {
            return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidWinnerJunctionChirho);
        }
        let mut checkpoint_chirho = Gd7ReadOnlyBranchCheckpointChirho {
            schema_chirho: GD7_READ_ONLY_BRANCH_CHECKPOINT_SCHEMA_V1_CHIRHO.to_owned(),
            transfer_identity_chirho: self.identity_chirho.clone(),
            transfer_identity_digest_chirho: gd7_held_evidence_transfer_identity_digest_chirho(
                &self.identity_chirho,
            )
            .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::InvalidIdentityChirho)?,
            evidence_checkpoint_ref_chirho: composition_chirho
                .evidence_checkpoint_ref_chirho()
                .to_owned(),
            held_view_checkpoint_ref_chirho: composition_chirho
                .held_view_checkpoint_ref_chirho()
                .to_owned(),
            held_view_bundle_root_ref_chirho: composition_chirho
                .held_view_bundle_root_ref_chirho()
                .to_owned(),
            fork_baseline_root_ref_chirho: composition_chirho
                .fork_baseline_root_ref_chirho()
                .to_owned(),
            prefix_root_ref_chirho,
            winner_history_root_ref_chirho: composition_chirho
                .winner_history_root_ref_chirho()
                .to_owned(),
            prefix_record_count_chirho: prefix_count_chirho,
            winner_suffix_record_count_chirho: winner_count_chirho,
            canonical_record_count_chirho,
            account_net_row_count_chirho: composition_chirho.matched_row_count_chirho(),
            key_id_chirho: self.held_signer_chirho.key_id_chirho(),
            sig_chirho: String::new(),
        };
        sign_value_chirho(
            &mut checkpoint_chirho,
            self.held_signer_chirho,
            |value_chirho| &mut value_chirho.sig_chirho,
        )?;
        validate_checkpoint_shape_chirho(&checkpoint_chirho)?;
        let bytes_chirho = canonical_json_chirho(&checkpoint_chirho)?;
        if bytes_chirho.len() > MAX_GD7_READ_ONLY_BRANCH_CHECKPOINT_BYTES_CHIRHO {
            return Err(Gd7ReadOnlyBranchRefusalChirho::OversizedObjectChirho);
        }
        let checkpoint_ref_chirho = digest_bytes_chirho(&bytes_chirho);
        create_exact_chirho(
            self.storage_chirho,
            &gd7_read_only_branch_checkpoint_path_chirho(&checkpoint_ref_chirho)?,
            &bytes_chirho,
            MAX_GD7_READ_ONLY_BRANCH_CHECKPOINT_BYTES_CHIRHO,
        )?;
        Ok(PreparedGd7ReadOnlyBranchChirho {
            checkpoint_ref_chirho,
            checkpoint_chirho,
        })
    }

    /// Publish one prepared, reverified read-only evidence head.
    ///
    /// This cannot make the branch live. The retained identity-derived genesis commitment and the
    /// losing reader's revalidated frozen cut are checked immediately before the atomic head write.
    pub fn install_prepared_read_only_branch_evidence_chirho(
        &self,
        losing_reader_chirho: &dyn LosingSuffixReaderChirho,
        losing_genesis_chirho: &ExpectedLedgerGenesisChirho,
        prepared_chirho: &PreparedGd7ReadOnlyBranchChirho,
    ) -> Result<ActiveGd7ReadOnlyBranchChirho, Gd7ReadOnlyBranchRefusalChirho> {
        self.require_held_branch_signer_chirho()?;
        let loaded_chirho = load_checkpoint_chirho(
            self.storage_chirho,
            &prepared_chirho.checkpoint_ref_chirho,
            &self.identity_chirho,
            self.held_signer_chirho,
        )?;
        if loaded_chirho != prepared_chirho.checkpoint_chirho {
            return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidCheckpointChirho);
        }
        let composition_chirho = self.verify_account_net_composition_chirho()?;
        require_checkpoint_composition_chirho(&loaded_chirho, &composition_chirho)?;
        self.require_exact_losing_genesis_chirho(losing_genesis_chirho)?;
        let losing_tail_chirho = losing_reader_chirho.revalidate_current_losing_tail_chirho()?;
        self.require_exact_losing_tail_chirho(&losing_tail_chirho)?;
        self.verify_checkpoint_branch_chirho(&loaded_chirho)?;
        let mut head_chirho = Gd7ReadOnlyBranchHeadChirho {
            schema_chirho: GD7_READ_ONLY_BRANCH_HEAD_SCHEMA_V1_CHIRHO.to_owned(),
            transfer_identity_digest_chirho: gd7_held_evidence_transfer_identity_digest_chirho(
                &self.identity_chirho,
            )
            .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::InvalidIdentityChirho)?,
            active_checkpoint_ref_chirho: prepared_chirho.checkpoint_ref_chirho.clone(),
            key_id_chirho: self.held_signer_chirho.key_id_chirho(),
            sig_chirho: String::new(),
        };
        sign_value_chirho(&mut head_chirho, self.held_signer_chirho, |value_chirho| {
            &mut value_chirho.sig_chirho
        })?;
        let head_bytes_chirho = canonical_json_chirho(&head_chirho)?;
        if head_bytes_chirho.len() > MAX_GD7_READ_ONLY_BRANCH_HEAD_BYTES_CHIRHO {
            return Err(Gd7ReadOnlyBranchRefusalChirho::OversizedObjectChirho);
        }
        self.storage_chirho
            .atomic_write_chirho(
                &gd7_read_only_branch_head_path_chirho(&self.identity_chirho)?,
                &head_bytes_chirho,
            )
            .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::StorageChirho)?;
        self.load_active_read_only_branch_evidence_chirho()?
            .ok_or(Gd7ReadOnlyBranchRefusalChirho::MissingObjectChirho)
    }

    pub fn prepare_and_install_read_only_branch_evidence_chirho(
        &self,
        losing_reader_chirho: &dyn LosingSuffixReaderChirho,
        losing_genesis_chirho: &ExpectedLedgerGenesisChirho,
    ) -> Result<ActiveGd7ReadOnlyBranchChirho, Gd7ReadOnlyBranchRefusalChirho> {
        let prepared_chirho = self.prepare_read_only_branch_evidence_chirho(
            losing_reader_chirho,
            losing_genesis_chirho,
        )?;
        self.install_prepared_read_only_branch_evidence_chirho(
            losing_reader_chirho,
            losing_genesis_chirho,
            &prepared_chirho,
        )
    }

    /// Reopen and reverify the exact head and both canonical history halves after restart.
    pub fn load_active_read_only_branch_evidence_chirho(
        &self,
    ) -> Result<Option<ActiveGd7ReadOnlyBranchChirho>, Gd7ReadOnlyBranchRefusalChirho> {
        self.require_held_branch_signer_chirho()?;
        let head_path_chirho = gd7_read_only_branch_head_path_chirho(&self.identity_chirho)?;
        let Some(head_bytes_chirho) = read_bounded_chirho(
            self.storage_chirho,
            &head_path_chirho,
            MAX_GD7_READ_ONLY_BRANCH_HEAD_BYTES_CHIRHO,
        )?
        else {
            return Ok(None);
        };
        let head_chirho: Gd7ReadOnlyBranchHeadChirho = parse_canonical_chirho(&head_bytes_chirho)?;
        verify_head_chirho(&head_chirho, &self.identity_chirho, self.held_signer_chirho)?;
        let active_chirho = self.verify_read_only_branch_checkpoint_at_ref_chirho(
            &head_chirho.active_checkpoint_ref_chirho,
        )?;
        let stable_head_chirho = read_bounded_chirho(
            self.storage_chirho,
            &head_path_chirho,
            MAX_GD7_READ_ONLY_BRANCH_HEAD_BYTES_CHIRHO,
        )?
        .ok_or(Gd7ReadOnlyBranchRefusalChirho::MissingObjectChirho)?;
        if stable_head_chirho != head_bytes_chirho {
            return Err(Gd7ReadOnlyBranchRefusalChirho::StaleEvidenceChirho);
        }
        Ok(Some(active_chirho))
    }

    /// Point-load and fully reverify one immutable branch checkpoint without trusting its head.
    pub(crate) fn verify_read_only_branch_checkpoint_at_ref_chirho(
        &self,
        checkpoint_ref_chirho: &str,
    ) -> Result<ActiveGd7ReadOnlyBranchChirho, Gd7ReadOnlyBranchRefusalChirho> {
        self.require_held_branch_signer_chirho()?;
        let checkpoint_chirho = load_checkpoint_chirho(
            self.storage_chirho,
            checkpoint_ref_chirho,
            &self.identity_chirho,
            self.held_signer_chirho,
        )?;
        let composition_chirho = self.verify_account_net_composition_at_checkpoint_chirho(
            &checkpoint_chirho.evidence_checkpoint_ref_chirho,
        )?;
        require_checkpoint_composition_chirho(&checkpoint_chirho, &composition_chirho)?;
        self.verify_checkpoint_branch_chirho(&checkpoint_chirho)?;
        Ok(ActiveGd7ReadOnlyBranchChirho {
            checkpoint_ref_chirho: checkpoint_ref_chirho.to_owned(),
            checkpoint_chirho,
        })
    }

    pub fn verify_active_read_only_branch_evidence_chirho(
        &self,
    ) -> Result<Option<VerifiedGd7ReadOnlyBranchChirho>, Gd7ReadOnlyBranchRefusalChirho> {
        let Some(active_chirho) = self.load_active_read_only_branch_evidence_chirho()? else {
            return Ok(None);
        };
        Ok(Some(VerifiedGd7ReadOnlyBranchChirho {
            checkpoint_ref_chirho: active_chirho.checkpoint_ref_chirho,
            prefix_root_ref_chirho: active_chirho.checkpoint_chirho.prefix_root_ref_chirho,
            winner_history_root_ref_chirho: active_chirho
                .checkpoint_chirho
                .winner_history_root_ref_chirho,
            canonical_record_count_chirho: active_chirho
                .checkpoint_chirho
                .canonical_record_count_chirho,
        }))
    }

    /// Reverify and visit the exact installed branch as canonical journal lines.
    ///
    /// The installed head and both history halves are fully verified before this second,
    /// oldest-to-newest walk begins. Each callback receives one canonical line without its LF;
    /// the genesis is first, followed by every record through the winner tail. The active head is
    /// reloaded afterward, so a caller may publish nothing unless the same checkpoint stayed
    /// active throughout the walk.
    pub(crate) fn visit_active_read_only_branch_canonical_lines_chirho<VisitChirho>(
        &self,
        expected_checkpoint_ref_chirho: &str,
        mut visit_chirho: VisitChirho,
    ) -> Result<VerifiedGd7ReadOnlyBranchChirho, Gd7ReadOnlyBranchRefusalChirho>
    where
        VisitChirho: FnMut(&str),
    {
        let active_chirho = self
            .load_active_read_only_branch_evidence_chirho()?
            .ok_or(Gd7ReadOnlyBranchRefusalChirho::MissingObjectChirho)?;
        if active_chirho.checkpoint_ref_chirho != expected_checkpoint_ref_chirho {
            return Err(Gd7ReadOnlyBranchRefusalChirho::StaleEvidenceChirho);
        }
        let checkpoint_chirho = &active_chirho.checkpoint_chirho;
        let prefix_root_chirho = verify_prefix_chain_with_lines_chirho(
            self.storage_chirho,
            &checkpoint_chirho.prefix_root_ref_chirho,
            &self.identity_chirho,
            self.held_signer_chirho,
            &mut visit_chirho,
        )?;
        let winner_count_chirho = self.verify_winner_suffix_with_lines_chirho(
            &checkpoint_chirho.winner_history_root_ref_chirho,
            &mut visit_chirho,
        )?;
        if prefix_root_chirho.record_count_chirho != checkpoint_chirho.prefix_record_count_chirho
            || winner_count_chirho != checkpoint_chirho.winner_suffix_record_count_chirho
        {
            return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidCheckpointChirho);
        }
        if self
            .load_active_read_only_branch_evidence_chirho()?
            .as_ref()
            != Some(&active_chirho)
        {
            return Err(Gd7ReadOnlyBranchRefusalChirho::StaleEvidenceChirho);
        }
        Ok(VerifiedGd7ReadOnlyBranchChirho {
            checkpoint_ref_chirho: active_chirho.checkpoint_ref_chirho,
            prefix_root_ref_chirho: checkpoint_chirho.prefix_root_ref_chirho.clone(),
            winner_history_root_ref_chirho: checkpoint_chirho
                .winner_history_root_ref_chirho
                .clone(),
            canonical_record_count_chirho: checkpoint_chirho.canonical_record_count_chirho,
        })
    }

    fn require_held_branch_signer_chirho(&self) -> Result<(), Gd7ReadOnlyBranchRefusalChirho> {
        if self.held_signer_chirho.key_id_chirho()
            != self
                .identity_chirho
                .reconciliation_identity_chirho
                .held_node_chirho
        {
            return Err(Gd7ReadOnlyBranchRefusalChirho::WrongHeldSignerChirho);
        }
        Ok(())
    }

    fn require_exact_losing_tail_chirho(
        &self,
        tail_chirho: &VerifiedLosingJournalTailChirho,
    ) -> Result<(), Gd7ReadOnlyBranchRefusalChirho> {
        let identity_chirho = &self.identity_chirho.reconciliation_identity_chirho;
        if tail_chirho.identity_chirho().genesis_digest_chirho().0
            != identity_chirho.losing_journal_genesis_digest_chirho
            || tail_chirho.record_epoch_chirho()
                != identity_chirho.losing_journal_tail_chirho.epoch_chirho
            || tail_chirho.coordinate_chirho().seq_chirho()
                != identity_chirho.losing_journal_tail_chirho.seq_chirho
            || tail_chirho.coordinate_chirho().record_digest_chirho().0
                != identity_chirho
                    .losing_journal_tail_chirho
                    .record_digest_chirho
        {
            return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidLosingTailChirho);
        }
        Ok(())
    }

    fn require_exact_losing_genesis_chirho(
        &self,
        genesis_chirho: &ExpectedLedgerGenesisChirho,
    ) -> Result<(), Gd7ReadOnlyBranchRefusalChirho> {
        if genesis_chirho.digest_chirho().0
            != self
                .identity_chirho
                .reconciliation_identity_chirho
                .losing_journal_genesis_digest_chirho
        {
            return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidLosingTailChirho);
        }
        Ok(())
    }

    fn stage_prefix_root_chirho(
        &self,
        losing_reader_chirho: &dyn LosingSuffixReaderChirho,
        losing_genesis_chirho: &ExpectedLedgerGenesisChirho,
        losing_tail_chirho: &VerifiedLosingJournalTailChirho,
    ) -> Result<Gd7ReadOnlyBranchPrefixRootChirho, Gd7ReadOnlyBranchRefusalChirho> {
        let identity_chirho = &self.identity_chirho.reconciliation_identity_chirho;
        let transfer_identity_digest_chirho =
            gd7_held_evidence_transfer_identity_digest_chirho(&self.identity_chirho)
                .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::InvalidIdentityChirho)?;
        let frozen_tail_chirho = losing_tail_chirho.coordinate_chirho().clone();
        let genesis_anchor_chirho = LosingSuffixCoordinateChirho::new_chirho(
            0,
            DigestChirho(identity_chirho.losing_journal_genesis_digest_chirho.clone()),
        );
        let mut cursor_chirho = None;
        let mut page_count_chirho = 0_u64;
        let mut record_count_chirho = 0_u64;
        let mut newer_page_ref_chirho = None;
        let mut saw_fork_chirho = identity_chirho.fork_chirho.seq_chirho == 0;
        loop {
            let mut request_chirho = LosingSuffixPageRequestChirho::new_chirho(
                losing_tail_chirho.identity_chirho().clone(),
                frozen_tail_chirho.clone(),
                genesis_anchor_chirho.clone(),
                MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO,
                MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
            );
            if let Some(cursor_chirho) = cursor_chirho.take() {
                request_chirho = request_chirho.with_cursor_chirho(cursor_chirho);
            }
            let page_chirho =
                losing_reader_chirho.read_verified_losing_suffix_page_chirho(&request_chirho)?;
            let retained_records_chirho: Vec<Gd7ReadOnlyBranchPrefixRecordChirho> = page_chirho
                .records_newest_first_chirho()
                .iter()
                .filter(|record_chirho| {
                    record_chirho.seq_chirho <= identity_chirho.fork_chirho.seq_chirho
                })
                .map(prefix_record_chirho)
                .collect::<Result<_, _>>()?;
            if !retained_records_chirho.is_empty() {
                if !saw_fork_chirho {
                    let newest_chirho = &retained_records_chirho[0];
                    if newest_chirho.record_chirho.seq_chirho
                        != identity_chirho.fork_chirho.seq_chirho
                        || newest_chirho.record_chirho.epoch_chirho
                            != identity_chirho.fork_chirho.epoch_chirho
                        || newest_chirho.record_digest_chirho
                            != identity_chirho.fork_chirho.record_digest_chirho
                    {
                        return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidPrefixChainChirho);
                    }
                    saw_fork_chirho = true;
                }
                record_count_chirho =
                    record_count_chirho
                        .checked_add(u64::try_from(retained_records_chirho.len()).map_err(
                            |_| Gd7ReadOnlyBranchRefusalChirho::ArithmeticOverflowChirho,
                        )?)
                        .ok_or(Gd7ReadOnlyBranchRefusalChirho::ArithmeticOverflowChirho)?;
                let page_wire_chirho = Gd7ReadOnlyBranchPrefixPageChirho {
                    schema_chirho: GD7_READ_ONLY_BRANCH_PREFIX_PAGE_SCHEMA_V1_CHIRHO.to_owned(),
                    transfer_identity_digest_chirho: transfer_identity_digest_chirho.clone(),
                    page_index_chirho: page_count_chirho,
                    newer_page_ref_chirho: newer_page_ref_chirho.clone(),
                    records_newest_first_chirho: retained_records_chirho,
                    cumulative_record_count_chirho: record_count_chirho,
                };
                let page_bytes_chirho = canonical_json_chirho(&page_wire_chirho)?;
                if page_bytes_chirho.len() > MAX_GD7_READ_ONLY_BRANCH_PREFIX_PAGE_BYTES_CHIRHO {
                    return Err(Gd7ReadOnlyBranchRefusalChirho::OversizedObjectChirho);
                }
                let page_ref_chirho = digest_bytes_chirho(&page_bytes_chirho);
                create_exact_chirho(
                    self.storage_chirho,
                    &gd7_read_only_branch_prefix_page_path_chirho(&page_ref_chirho)?,
                    &page_bytes_chirho,
                    MAX_GD7_READ_ONLY_BRANCH_PREFIX_PAGE_BYTES_CHIRHO,
                )?;
                newer_page_ref_chirho = Some(page_ref_chirho);
                page_count_chirho = page_count_chirho
                    .checked_add(1)
                    .ok_or(Gd7ReadOnlyBranchRefusalChirho::ArithmeticOverflowChirho)?;
            }
            if page_chirho.reached_anchor_chirho() {
                break;
            }
            cursor_chirho = page_chirho.next_cursor_chirho().cloned();
            if cursor_chirho.is_none() {
                return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidPrefixChainChirho);
            }
        }
        if !saw_fork_chirho || record_count_chirho != identity_chirho.fork_chirho.seq_chirho {
            return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidPrefixChainChirho);
        }
        Ok(Gd7ReadOnlyBranchPrefixRootChirho {
            schema_chirho: GD7_READ_ONLY_BRANCH_PREFIX_ROOT_SCHEMA_V1_CHIRHO.to_owned(),
            transfer_identity_chirho: self.identity_chirho.clone(),
            transfer_identity_digest_chirho,
            genesis_line_chirho: losing_genesis_chirho.canonical_line_chirho().to_owned(),
            losing_tail_epoch_chirho: losing_tail_chirho.record_epoch_chirho(),
            losing_tail_seq_chirho: frozen_tail_chirho.seq_chirho(),
            losing_tail_record_digest_chirho: frozen_tail_chirho.record_digest_chirho().0.clone(),
            oldest_page_ref_chirho: newer_page_ref_chirho,
            page_count_chirho,
            record_count_chirho,
            key_id_chirho: self.held_signer_chirho.key_id_chirho(),
            sig_chirho: String::new(),
        })
    }

    fn verify_branch_halves_chirho(
        &self,
        prefix_root_ref_chirho: &str,
        winner_history_root_ref_chirho: &str,
    ) -> Result<(u64, u64), Gd7ReadOnlyBranchRefusalChirho> {
        let prefix_root_chirho = verify_prefix_chain_chirho(
            self.storage_chirho,
            prefix_root_ref_chirho,
            &self.identity_chirho,
            self.held_signer_chirho,
        )?;
        let winner_count_chirho =
            self.verify_winner_suffix_chirho(winner_history_root_ref_chirho)?;
        Ok((prefix_root_chirho.record_count_chirho, winner_count_chirho))
    }

    fn verify_winner_suffix_chirho(
        &self,
        winner_history_root_ref_chirho: &str,
    ) -> Result<u64, Gd7ReadOnlyBranchRefusalChirho> {
        self.verify_winner_suffix_with_records_chirho(
            winner_history_root_ref_chirho,
            |_record_chirho| {},
        )
    }

    fn verify_winner_suffix_with_lines_chirho<VisitChirho>(
        &self,
        winner_history_root_ref_chirho: &str,
        visit_chirho: &mut VisitChirho,
    ) -> Result<u64, Gd7ReadOnlyBranchRefusalChirho>
    where
        VisitChirho: FnMut(&str),
    {
        let mut serialization_refusal_chirho = false;
        let count_chirho = self.verify_winner_suffix_with_records_chirho(
            winner_history_root_ref_chirho,
            |record_chirho| match canonical_ledger_record_line_chirho(record_chirho) {
                Ok(line_chirho) => visit_chirho(&line_chirho),
                Err(_error_chirho) => serialization_refusal_chirho = true,
            },
        )?;
        if serialization_refusal_chirho {
            return Err(Gd7ReadOnlyBranchRefusalChirho::SerializationChirho);
        }
        Ok(count_chirho)
    }

    fn verify_winner_suffix_with_records_chirho<VisitChirho>(
        &self,
        winner_history_root_ref_chirho: &str,
        mut visit_chirho: VisitChirho,
    ) -> Result<u64, Gd7ReadOnlyBranchRefusalChirho>
    where
        VisitChirho: FnMut(&LedgerRecordChirho),
    {
        let reconciliation_identity_chirho = &self.identity_chirho.reconciliation_identity_chirho;
        let history_identity_chirho = Gd7WinnerHistoryIdentityChirho::new_chirho(
            reconciliation_identity_chirho.clone(),
            self.identity_chirho
                .winner_handoff_attempt_digest_chirho
                .clone(),
        )?;
        let mut expected_seq_chirho = reconciliation_identity_chirho
            .fork_chirho
            .seq_chirho
            .checked_add(1)
            .ok_or(Gd7ReadOnlyBranchRefusalChirho::ArithmeticOverflowChirho)?;
        let mut previous_digest_chirho = DigestChirho(
            reconciliation_identity_chirho
                .fork_chirho
                .record_digest_chirho
                .clone(),
        );
        let mut observed_count_chirho = 0_u64;
        let mut terminal_epoch_chirho =
            Some(reconciliation_identity_chirho.fork_chirho.epoch_chirho);
        let mut terminal_digest_chirho = Some(DigestChirho(
            reconciliation_identity_chirho
                .fork_chirho
                .record_digest_chirho
                .clone(),
        ));
        let mut chain_invalid_chirho = false;
        let chain_chirho = verify_complete_gd7_winner_history_chain_with_records_chirho(
            self.storage_chirho,
            winner_history_root_ref_chirho,
            &history_identity_chirho,
            self.winner_verifier_chirho,
            self.winner_ledger_verifier_chirho,
            |record_chirho| {
                if chain_invalid_chirho {
                    return;
                }
                let Ok(digest_chirho) = record_digest_chirho(record_chirho) else {
                    chain_invalid_chirho = true;
                    return;
                };
                if record_chirho.seq_chirho != expected_seq_chirho
                    || record_chirho.prev_chirho != previous_digest_chirho
                {
                    chain_invalid_chirho = true;
                    return;
                }
                previous_digest_chirho = digest_chirho.clone();
                terminal_digest_chirho = Some(digest_chirho);
                terminal_epoch_chirho = Some(record_chirho.epoch_chirho);
                let Some(next_seq_chirho) = expected_seq_chirho.checked_add(1) else {
                    chain_invalid_chirho = true;
                    return;
                };
                let Some(next_count_chirho) = observed_count_chirho.checked_add(1) else {
                    chain_invalid_chirho = true;
                    return;
                };
                expected_seq_chirho = next_seq_chirho;
                observed_count_chirho = next_count_chirho;
                visit_chirho(record_chirho);
            },
        )?;
        let expected_count_chirho = reconciliation_identity_chirho
            .winner_journal_tail_chirho
            .seq_chirho
            .checked_sub(reconciliation_identity_chirho.fork_chirho.seq_chirho)
            .ok_or(Gd7ReadOnlyBranchRefusalChirho::InvalidWinnerJunctionChirho)?;
        if chain_invalid_chirho
            || observed_count_chirho != expected_count_chirho
            || chain_chirho.root_chirho().object_digest_chirho() != winner_history_root_ref_chirho
            || terminal_epoch_chirho
                != Some(
                    reconciliation_identity_chirho
                        .winner_journal_tail_chirho
                        .epoch_chirho,
                )
            || terminal_digest_chirho
                .as_ref()
                .map(|digest_chirho| &digest_chirho.0)
                != Some(
                    &reconciliation_identity_chirho
                        .winner_journal_tail_chirho
                        .record_digest_chirho,
                )
        {
            return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidWinnerJunctionChirho);
        }
        Ok(observed_count_chirho)
    }

    fn verify_checkpoint_branch_chirho(
        &self,
        checkpoint_chirho: &Gd7ReadOnlyBranchCheckpointChirho,
    ) -> Result<(), Gd7ReadOnlyBranchRefusalChirho> {
        validate_checkpoint_shape_chirho(checkpoint_chirho)?;
        let (prefix_count_chirho, winner_count_chirho) = self.verify_branch_halves_chirho(
            &checkpoint_chirho.prefix_root_ref_chirho,
            &checkpoint_chirho.winner_history_root_ref_chirho,
        )?;
        if prefix_count_chirho != checkpoint_chirho.prefix_record_count_chirho
            || winner_count_chirho != checkpoint_chirho.winner_suffix_record_count_chirho
            || prefix_count_chirho
                .checked_add(winner_count_chirho)
                .ok_or(Gd7ReadOnlyBranchRefusalChirho::ArithmeticOverflowChirho)?
                != checkpoint_chirho.canonical_record_count_chirho
        {
            return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidCheckpointChirho);
        }
        Ok(())
    }
}

fn prefix_record_chirho(
    record_chirho: &LedgerRecordChirho,
) -> Result<Gd7ReadOnlyBranchPrefixRecordChirho, Gd7ReadOnlyBranchRefusalChirho> {
    Ok(Gd7ReadOnlyBranchPrefixRecordChirho {
        record_digest_chirho: record_digest_chirho(record_chirho)?.0,
        record_chirho: record_chirho.clone(),
    })
}

fn record_digest_chirho(
    record_chirho: &LedgerRecordChirho,
) -> Result<DigestChirho, Gd7ReadOnlyBranchRefusalChirho> {
    let line_chirho = canonical_ledger_record_line_chirho(record_chirho)
        .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::SerializationChirho)?;
    Ok(stored_line_digest_chirho(&line_chirho))
}

fn persist_signed_prefix_root_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    mut root_chirho: Gd7ReadOnlyBranchPrefixRootChirho,
) -> Result<String, Gd7ReadOnlyBranchRefusalChirho> {
    sign_value_chirho(&mut root_chirho, held_signer_chirho, |value_chirho| {
        &mut value_chirho.sig_chirho
    })?;
    validate_prefix_root_shape_chirho(&root_chirho)?;
    let bytes_chirho = canonical_json_chirho(&root_chirho)?;
    if bytes_chirho.len() > MAX_GD7_READ_ONLY_BRANCH_PREFIX_ROOT_BYTES_CHIRHO {
        return Err(Gd7ReadOnlyBranchRefusalChirho::OversizedObjectChirho);
    }
    let object_digest_chirho = digest_bytes_chirho(&bytes_chirho);
    create_exact_chirho(
        storage_chirho,
        &gd7_read_only_branch_prefix_root_path_chirho(&object_digest_chirho)?,
        &bytes_chirho,
        MAX_GD7_READ_ONLY_BRANCH_PREFIX_ROOT_BYTES_CHIRHO,
    )?;
    Ok(object_digest_chirho)
}

fn verify_prefix_chain_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    root_ref_chirho: &str,
    expected_identity_chirho: &Gd7HeldEvidenceTransferIdentityChirho,
    held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<Gd7ReadOnlyBranchPrefixRootChirho, Gd7ReadOnlyBranchRefusalChirho> {
    verify_prefix_chain_with_lines_chirho(
        storage_chirho,
        root_ref_chirho,
        expected_identity_chirho,
        held_verifier_chirho,
        &mut |_line_chirho| {},
    )
}

fn verify_prefix_chain_with_lines_chirho<VisitChirho>(
    storage_chirho: &dyn LedgerStoragePortChirho,
    root_ref_chirho: &str,
    expected_identity_chirho: &Gd7HeldEvidenceTransferIdentityChirho,
    held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    visit_chirho: &mut VisitChirho,
) -> Result<Gd7ReadOnlyBranchPrefixRootChirho, Gd7ReadOnlyBranchRefusalChirho>
where
    VisitChirho: FnMut(&str),
{
    let root_bytes_chirho = read_bounded_chirho(
        storage_chirho,
        &gd7_read_only_branch_prefix_root_path_chirho(root_ref_chirho)?,
        MAX_GD7_READ_ONLY_BRANCH_PREFIX_ROOT_BYTES_CHIRHO,
    )?
    .ok_or(Gd7ReadOnlyBranchRefusalChirho::MissingObjectChirho)?;
    if digest_bytes_chirho(&root_bytes_chirho) != root_ref_chirho {
        return Err(Gd7ReadOnlyBranchRefusalChirho::ObjectDigestMismatchChirho);
    }
    let root_chirho: Gd7ReadOnlyBranchPrefixRootChirho =
        parse_canonical_chirho(&root_bytes_chirho)?;
    validate_prefix_root_shape_chirho(&root_chirho)?;
    if root_chirho.transfer_identity_chirho != *expected_identity_chirho {
        return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidIdentityChirho);
    }
    verify_value_signature_chirho(&root_chirho, held_verifier_chirho, |value_chirho| {
        &mut value_chirho.sig_chirho
    })?;
    if root_chirho.key_id_chirho != held_verifier_chirho.key_id_chirho() {
        return Err(Gd7ReadOnlyBranchRefusalChirho::WrongHeldSignerChirho);
    }
    visit_chirho(&root_chirho.genesis_line_chirho);
    let identity_chirho = &expected_identity_chirho.reconciliation_identity_chirho;
    let mut page_ref_chirho = root_chirho.oldest_page_ref_chirho.clone();
    let mut expected_page_index_chirho = root_chirho.page_count_chirho.saturating_sub(1);
    let mut expected_seq_chirho = 1_u64;
    let mut previous_digest_chirho =
        DigestChirho(identity_chirho.losing_journal_genesis_digest_chirho.clone());
    let mut observed_count_chirho = 0_u64;
    let mut expected_cumulative_count_chirho = root_chirho.record_count_chirho;
    for _page_offset_chirho in 0..root_chirho.page_count_chirho {
        let current_ref_chirho = page_ref_chirho
            .take()
            .ok_or(Gd7ReadOnlyBranchRefusalChirho::InvalidPrefixChainChirho)?;
        let bytes_chirho = read_bounded_chirho(
            storage_chirho,
            &gd7_read_only_branch_prefix_page_path_chirho(&current_ref_chirho)?,
            MAX_GD7_READ_ONLY_BRANCH_PREFIX_PAGE_BYTES_CHIRHO,
        )?
        .ok_or(Gd7ReadOnlyBranchRefusalChirho::MissingObjectChirho)?;
        if digest_bytes_chirho(&bytes_chirho) != current_ref_chirho {
            return Err(Gd7ReadOnlyBranchRefusalChirho::ObjectDigestMismatchChirho);
        }
        let page_chirho: Gd7ReadOnlyBranchPrefixPageChirho = parse_canonical_chirho(&bytes_chirho)?;
        if page_chirho.schema_chirho != GD7_READ_ONLY_BRANCH_PREFIX_PAGE_SCHEMA_V1_CHIRHO
            || page_chirho.transfer_identity_digest_chirho
                != root_chirho.transfer_identity_digest_chirho
            || page_chirho.page_index_chirho != expected_page_index_chirho
            || page_chirho.records_newest_first_chirho.is_empty()
            || page_chirho.records_newest_first_chirho.len() > MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO
        {
            return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidPrefixShapeChirho);
        }
        for stored_chirho in page_chirho.records_newest_first_chirho.iter().rev() {
            let line_chirho = canonical_ledger_record_line_chirho(&stored_chirho.record_chirho)
                .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::SerializationChirho)?;
            let digest_chirho = stored_line_digest_chirho(&line_chirho);
            if stored_chirho.record_digest_chirho != digest_chirho.0
                || stored_chirho.record_chirho.seq_chirho != expected_seq_chirho
                || stored_chirho.record_chirho.prev_chirho != previous_digest_chirho
            {
                return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidPrefixChainChirho);
            }
            previous_digest_chirho = digest_chirho;
            expected_seq_chirho = expected_seq_chirho
                .checked_add(1)
                .ok_or(Gd7ReadOnlyBranchRefusalChirho::ArithmeticOverflowChirho)?;
            observed_count_chirho = observed_count_chirho
                .checked_add(1)
                .ok_or(Gd7ReadOnlyBranchRefusalChirho::ArithmeticOverflowChirho)?;
            visit_chirho(&line_chirho);
        }
        if page_chirho.cumulative_record_count_chirho != expected_cumulative_count_chirho {
            return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidPrefixShapeChirho);
        }
        expected_cumulative_count_chirho = expected_cumulative_count_chirho
            .checked_sub(
                u64::try_from(page_chirho.records_newest_first_chirho.len())
                    .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::ArithmeticOverflowChirho)?,
            )
            .ok_or(Gd7ReadOnlyBranchRefusalChirho::InvalidPrefixShapeChirho)?;
        page_ref_chirho = page_chirho.newer_page_ref_chirho;
        expected_page_index_chirho = expected_page_index_chirho.saturating_sub(1);
    }
    if page_ref_chirho.is_some()
        || observed_count_chirho != root_chirho.record_count_chirho
        || expected_cumulative_count_chirho != 0
        || expected_seq_chirho
            != identity_chirho
                .fork_chirho
                .seq_chirho
                .checked_add(1)
                .ok_or(Gd7ReadOnlyBranchRefusalChirho::ArithmeticOverflowChirho)?
        || previous_digest_chirho.0 != identity_chirho.fork_chirho.record_digest_chirho
    {
        return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidPrefixChainChirho);
    }
    Ok(root_chirho)
}

fn validate_prefix_root_shape_chirho(
    root_chirho: &Gd7ReadOnlyBranchPrefixRootChirho,
) -> Result<(), Gd7ReadOnlyBranchRefusalChirho> {
    let identity_chirho = &root_chirho
        .transfer_identity_chirho
        .reconciliation_identity_chirho;
    let identity_digest_chirho =
        gd7_held_evidence_transfer_identity_digest_chirho(&root_chirho.transfer_identity_chirho)
            .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::InvalidIdentityChirho)?;
    let empty_chirho = identity_chirho.fork_chirho.seq_chirho == 0
        && identity_chirho.fork_chirho.record_digest_chirho
            == identity_chirho.losing_journal_genesis_digest_chirho
        && root_chirho.page_count_chirho == 0
        && root_chirho.record_count_chirho == 0
        && root_chirho.oldest_page_ref_chirho.is_none();
    let nonempty_chirho = identity_chirho.fork_chirho.seq_chirho > 0
        && root_chirho.page_count_chirho > 0
        && root_chirho.record_count_chirho == identity_chirho.fork_chirho.seq_chirho
        && root_chirho.oldest_page_ref_chirho.is_some();
    let genesis_valid_chirho = root_chirho.genesis_line_chirho.len()
        <= MAX_EXPECTED_GENESIS_LINE_BYTES_CHIRHO
        && stored_line_digest_chirho(&root_chirho.genesis_line_chirho).0
            == identity_chirho.losing_journal_genesis_digest_chirho
        && matches!(
            parse_canonical_ledger_journal_line_chirho(&root_chirho.genesis_line_chirho),
            Ok(LedgerJournalLineChirho::GenesisChirho(_))
        );
    if root_chirho.schema_chirho != GD7_READ_ONLY_BRANCH_PREFIX_ROOT_SCHEMA_V1_CHIRHO
        || root_chirho.transfer_identity_digest_chirho != identity_digest_chirho
        || !genesis_valid_chirho
        || root_chirho.losing_tail_epoch_chirho
            != identity_chirho.losing_journal_tail_chirho.epoch_chirho
        || root_chirho.losing_tail_seq_chirho
            != identity_chirho.losing_journal_tail_chirho.seq_chirho
        || root_chirho.losing_tail_record_digest_chirho
            != identity_chirho
                .losing_journal_tail_chirho
                .record_digest_chirho
        || (!empty_chirho && !nonempty_chirho)
        || root_chirho
            .oldest_page_ref_chirho
            .as_deref()
            .is_some_and(|digest_chirho| !is_lower_hex_digest_chirho(digest_chirho))
        || !is_lower_hex_digest_chirho(&root_chirho.key_id_chirho)
        || root_chirho.sig_chirho.is_empty()
    {
        return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidPrefixShapeChirho);
    }
    Ok(())
}

fn validate_checkpoint_shape_chirho(
    checkpoint_chirho: &Gd7ReadOnlyBranchCheckpointChirho,
) -> Result<(), Gd7ReadOnlyBranchRefusalChirho> {
    let identity_digest_chirho = gd7_held_evidence_transfer_identity_digest_chirho(
        &checkpoint_chirho.transfer_identity_chirho,
    )
    .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::InvalidIdentityChirho)?;
    let identity_chirho = &checkpoint_chirho
        .transfer_identity_chirho
        .reconciliation_identity_chirho;
    if checkpoint_chirho.schema_chirho != GD7_READ_ONLY_BRANCH_CHECKPOINT_SCHEMA_V1_CHIRHO
        || checkpoint_chirho.transfer_identity_digest_chirho != identity_digest_chirho
        || checkpoint_chirho.held_view_checkpoint_ref_chirho
            != checkpoint_chirho
                .transfer_identity_chirho
                .held_view_transfer_checkpoint_ref_chirho
        || checkpoint_chirho.prefix_record_count_chirho != identity_chirho.fork_chirho.seq_chirho
        || checkpoint_chirho.canonical_record_count_chirho
            != identity_chirho.winner_journal_tail_chirho.seq_chirho
        || checkpoint_chirho
            .prefix_record_count_chirho
            .checked_add(checkpoint_chirho.winner_suffix_record_count_chirho)
            != Some(checkpoint_chirho.canonical_record_count_chirho)
        || [
            &checkpoint_chirho.evidence_checkpoint_ref_chirho,
            &checkpoint_chirho.held_view_checkpoint_ref_chirho,
            &checkpoint_chirho.held_view_bundle_root_ref_chirho,
            &checkpoint_chirho.fork_baseline_root_ref_chirho,
            &checkpoint_chirho.prefix_root_ref_chirho,
            &checkpoint_chirho.winner_history_root_ref_chirho,
            &checkpoint_chirho.key_id_chirho,
        ]
        .into_iter()
        .any(|digest_chirho| !is_lower_hex_digest_chirho(digest_chirho))
        || checkpoint_chirho.sig_chirho.is_empty()
    {
        return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidCheckpointChirho);
    }
    Ok(())
}

fn require_checkpoint_composition_chirho(
    checkpoint_chirho: &Gd7ReadOnlyBranchCheckpointChirho,
    composition_chirho: &VerifiedGd7AccountNetCompositionChirho,
) -> Result<(), Gd7ReadOnlyBranchRefusalChirho> {
    if checkpoint_chirho.evidence_checkpoint_ref_chirho
        != composition_chirho.evidence_checkpoint_ref_chirho()
        || checkpoint_chirho.held_view_checkpoint_ref_chirho
            != composition_chirho.held_view_checkpoint_ref_chirho()
        || checkpoint_chirho.held_view_bundle_root_ref_chirho
            != composition_chirho.held_view_bundle_root_ref_chirho()
        || checkpoint_chirho.fork_baseline_root_ref_chirho
            != composition_chirho.fork_baseline_root_ref_chirho()
        || checkpoint_chirho.winner_history_root_ref_chirho
            != composition_chirho.winner_history_root_ref_chirho()
        || checkpoint_chirho.winner_suffix_record_count_chirho
            != composition_chirho.applied_record_count_chirho()
        || checkpoint_chirho.account_net_row_count_chirho
            != composition_chirho.matched_row_count_chirho()
    {
        return Err(Gd7ReadOnlyBranchRefusalChirho::StaleEvidenceChirho);
    }
    Ok(())
}

fn load_checkpoint_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    checkpoint_ref_chirho: &str,
    expected_identity_chirho: &Gd7HeldEvidenceTransferIdentityChirho,
    held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<Gd7ReadOnlyBranchCheckpointChirho, Gd7ReadOnlyBranchRefusalChirho> {
    let bytes_chirho = read_bounded_chirho(
        storage_chirho,
        &gd7_read_only_branch_checkpoint_path_chirho(checkpoint_ref_chirho)?,
        MAX_GD7_READ_ONLY_BRANCH_CHECKPOINT_BYTES_CHIRHO,
    )?
    .ok_or(Gd7ReadOnlyBranchRefusalChirho::MissingObjectChirho)?;
    if digest_bytes_chirho(&bytes_chirho) != checkpoint_ref_chirho {
        return Err(Gd7ReadOnlyBranchRefusalChirho::ObjectDigestMismatchChirho);
    }
    let checkpoint_chirho: Gd7ReadOnlyBranchCheckpointChirho =
        parse_canonical_chirho(&bytes_chirho)?;
    validate_checkpoint_shape_chirho(&checkpoint_chirho)?;
    if checkpoint_chirho.transfer_identity_chirho != *expected_identity_chirho {
        return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidIdentityChirho);
    }
    verify_value_signature_chirho(&checkpoint_chirho, held_verifier_chirho, |value_chirho| {
        &mut value_chirho.sig_chirho
    })?;
    if checkpoint_chirho.key_id_chirho != held_verifier_chirho.key_id_chirho() {
        return Err(Gd7ReadOnlyBranchRefusalChirho::WrongHeldSignerChirho);
    }
    Ok(checkpoint_chirho)
}

fn verify_head_chirho(
    head_chirho: &Gd7ReadOnlyBranchHeadChirho,
    expected_identity_chirho: &Gd7HeldEvidenceTransferIdentityChirho,
    held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<(), Gd7ReadOnlyBranchRefusalChirho> {
    let expected_digest_chirho =
        gd7_held_evidence_transfer_identity_digest_chirho(expected_identity_chirho)
            .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::InvalidIdentityChirho)?;
    if head_chirho.schema_chirho != GD7_READ_ONLY_BRANCH_HEAD_SCHEMA_V1_CHIRHO
        || head_chirho.transfer_identity_digest_chirho != expected_digest_chirho
        || !is_lower_hex_digest_chirho(&head_chirho.active_checkpoint_ref_chirho)
        || !is_lower_hex_digest_chirho(&head_chirho.key_id_chirho)
        || head_chirho.sig_chirho.is_empty()
    {
        return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidCheckpointChirho);
    }
    verify_value_signature_chirho(head_chirho, held_verifier_chirho, |value_chirho| {
        &mut value_chirho.sig_chirho
    })?;
    if head_chirho.key_id_chirho != held_verifier_chirho.key_id_chirho() {
        return Err(Gd7ReadOnlyBranchRefusalChirho::WrongHeldSignerChirho);
    }
    Ok(())
}

fn sign_value_chirho<ValueChirho: Clone + Serialize>(
    value_chirho: &mut ValueChirho,
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    signature_chirho: impl Fn(&mut ValueChirho) -> &mut String,
) -> Result<(), Gd7ReadOnlyBranchRefusalChirho> {
    signature_chirho(value_chirho).clear();
    let unsigned_bytes_chirho = canonical_json_chirho(value_chirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::SerializationChirho)?;
    *signature_chirho(value_chirho) = signer_chirho
        .sign_chirho(unsigned_line_chirho)
        .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::SigningChirho)?;
    Ok(())
}

fn verify_value_signature_chirho<ValueChirho: Clone + Serialize>(
    value_chirho: &ValueChirho,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    signature_chirho: impl Fn(&mut ValueChirho) -> &mut String,
) -> Result<(), Gd7ReadOnlyBranchRefusalChirho> {
    let mut unsigned_chirho = value_chirho.clone();
    let signature_value_chirho = signature_chirho(&mut unsigned_chirho).clone();
    signature_chirho(&mut unsigned_chirho).clear();
    let unsigned_bytes_chirho = canonical_json_chirho(&unsigned_chirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::SerializationChirho)?;
    if !verifier_chirho.verify_chirho(unsigned_line_chirho, &signature_value_chirho) {
        return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidSignatureChirho);
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho;
