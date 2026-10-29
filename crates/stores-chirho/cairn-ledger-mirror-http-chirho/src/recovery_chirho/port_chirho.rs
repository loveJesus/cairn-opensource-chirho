// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Production selection of the exact two-holder F1 recovery candidate.

use super::head_chirho::{RECOVERY_SOURCE_BOOTSTRAP_CHIRHO, RECOVERY_SOURCE_LIVE_CHIRHO};
use super::{
    LedgerMirrorDenseChainHasherChirho, LedgerMirrorOrdinaryTermAcceptanceRequestChirho,
    LedgerMirrorOrdinaryTermAcceptanceRequestInputChirho, LedgerMirrorRecoveryHeadReceiptChirho,
    LedgerMirrorRecoveryHeadRequestChirho, LedgerMirrorRecoveryHeadRequestInputChirho,
    LedgerMirrorVerifiedPrefixManifestChirho, LedgerMirrorVerifiedPrefixManifestInputChirho,
    LedgerMirrorVerifiedPrefixPageChirho, VerifiedLedgerMirrorRecoveryHeadPairChirho,
    PREFIX_PAGE_MAX_RECORDS_CHIRHO,
};
use crate::client_chirho::{
    private_mesh_agent_chirho, require_current_leader_view_chirho, LedgerMirrorDirectoryChirho,
};
use crate::store_chirho::LedgerMirrorFollowerStoreChirho;
use anyhow::{bail, Result};
use cairn_ledger_log_chirho::append_mirror_chirho::LedgerAppendMirrorTailChirho;
use cairn_ledger_log_chirho::losing_suffix_chirho::{
    LosingSuffixCoordinateChirho, LosingSuffixJournalIdentityChirho, LosingSuffixPageRequestChirho,
    LosingSuffixReadErrorChirho, VerifiedLosingJournalTailChirho,
};
use cairn_ledger_log_chirho::recovery_mirror_chirho::{
    LedgerMirrorOrdinaryTermAcceptanceChallengeChirho,
    LedgerMirrorOrdinaryTermAcceptanceEvidenceSourceChirho, LedgerMirrorPrefixSourceChirho,
    LedgerMirrorRecoveryCandidateChirho, LedgerMirrorRecoveryCandidateInputChirho,
    LedgerMirrorRecoveryPortChirho, LedgerMirrorRecoveryPortErrorChirho,
    RawCanonicalGroupIdDigestChirho,
};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::wire_chirho::{
    parse_canonical_ledger_journal_line_chirho, stored_line_digest_chirho, LedgerJournalLineChirho,
};
use cairn_mirror_chirho::{
    MirrorHolderSetChirho, MirrorLeadershipViewChirho, MirrorResidencyPolicyChirho,
};
use cairn_tenant_placement_authority_chirho::VerifiedTenantPlacementChirho;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub(crate) struct ProductionLedgerMirrorRecoveryPortChirho {
    local_node_id_chirho: String,
    sign_root_chirho: PathBuf,
    placement_chirho: Arc<VerifiedTenantPlacementChirho>,
    election_view_chirho: Arc<dyn MirrorLeadershipViewChirho>,
    residency_chirho: MirrorResidencyPolicyChirho,
    directory_chirho: LedgerMirrorDirectoryChirho,
    follower_store_chirho: Arc<LedgerMirrorFollowerStoreChirho>,
    agent_chirho: ureq::Agent,
    operation_lock_chirho: Mutex<()>,
}

pub(crate) struct ProductionLedgerMirrorRecoveryInputChirho {
    pub local_node_id_chirho: String,
    pub sign_root_chirho: PathBuf,
    pub placement_chirho: Arc<VerifiedTenantPlacementChirho>,
    pub election_view_chirho: Arc<dyn MirrorLeadershipViewChirho>,
    pub residency_chirho: MirrorResidencyPolicyChirho,
    pub directory_chirho: LedgerMirrorDirectoryChirho,
    pub follower_store_chirho: Arc<LedgerMirrorFollowerStoreChirho>,
}

/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/item7-f1-mirror-recovery-adoption-chirho.md`.
pub(super) fn require_common_bootstrap_pair_chirho(
    first_chirho: &LedgerMirrorRecoveryHeadReceiptChirho,
    second_chirho: &LedgerMirrorRecoveryHeadReceiptChirho,
) -> Result<()> {
    if [first_chirho, second_chirho].iter().all(|receipt_chirho| {
        receipt_chirho.source_head_kind_chirho() == RECOVERY_SOURCE_BOOTSTRAP_CHIRHO
    }) {
        VerifiedLedgerMirrorRecoveryHeadPairChirho::join_chirho(
            first_chirho.clone(),
            second_chirho.clone(),
        )
        .map_err(|_| anyhow::anyhow!("LedgerMirrorCurrentHolderPrefixBindingRefusedChirho"))?;
    }
    Ok(())
}

impl ProductionLedgerMirrorRecoveryPortChirho {
    pub(crate) fn new_chirho(input_chirho: ProductionLedgerMirrorRecoveryInputChirho) -> Self {
        Self {
            local_node_id_chirho: input_chirho.local_node_id_chirho,
            sign_root_chirho: input_chirho.sign_root_chirho,
            placement_chirho: input_chirho.placement_chirho,
            election_view_chirho: input_chirho.election_view_chirho,
            residency_chirho: input_chirho.residency_chirho,
            directory_chirho: input_chirho.directory_chirho,
            follower_store_chirho: input_chirho.follower_store_chirho,
            agent_chirho: private_mesh_agent_chirho(),
            operation_lock_chirho: Mutex::new(()),
        }
    }

    fn current_leader_view_chirho(&self) -> Result<cairn_mirror_chirho::JoinedMirrorViewChirho> {
        require_current_leader_view_chirho(
            &self.local_node_id_chirho,
            &self.placement_chirho,
            self.election_view_chirho.as_ref(),
            &self.residency_chirho,
        )
    }

    /// A recovery head may come from the current placement or its one signed predecessor.
    ///
    /// The candidate constructor separately derives its `current_*` term and membership-view fields
    /// from a fresh join. This predicate therefore widens only the historical assignment binding;
    /// current election and membership authority never flow from the recovery head.
    /// New bootstrap heads still bind the current placement, so the allowance closes automatically
    /// when the verified current record advances again.
    fn recovery_assignment_matches_chirho(&self, assignment_digest_chirho: &str) -> bool {
        assignment_digest_chirho == self.placement_chirho.assignment_digest_chirho()
            || self
                .placement_chirho
                .intent_chirho()
                .previous_assignment_digest_chirho
                .as_deref()
                .is_some_and(|previous_chirho| previous_chirho == assignment_digest_chirho)
    }

    fn read_remote_recovery_head_chirho(
        &self,
        joined_chirho: &cairn_mirror_chirho::JoinedMirrorViewChirho,
        holder_node_id_chirho: &str,
    ) -> Result<Option<(LedgerMirrorRecoveryHeadReceiptChirho, Vec<u8>)>> {
        // Keep construction above the bounded read retry. A frozen signed term lets a behind holder
        // converge while making an ahead holder exhaust rather than walking local authority forward.
        let request_chirho = LedgerMirrorRecoveryHeadRequestChirho::sign_chirho(
            LedgerMirrorRecoveryHeadRequestInputChirho {
                requester_node_id_chirho: self.local_node_id_chirho.clone(),
                target_node_id_chirho: holder_node_id_chirho.to_string(),
                consistency_group_digest_chirho: joined_chirho
                    .view_chirho()
                    .consistency_group_digest_chirho()
                    .to_string(),
                assignment_digest_chirho: self
                    .placement_chirho
                    .assignment_digest_chirho()
                    .to_string(),
                expected_term_chirho: joined_chirho.term_chirho(),
                membership_view_digest_chirho: joined_chirho.view_chirho().view_digest_chirho(),
            },
            &self.sign_root_chirho,
        )?;
        let Some(wire_chirho) = self.directory_chirho.read_recovery_head_chirho(
            holder_node_id_chirho,
            &request_chirho,
            &self.agent_chirho,
        )?
        else {
            return Ok(None);
        };
        let receipt_chirho = LedgerMirrorRecoveryHeadReceiptChirho::decode_and_verify_chirho(
            &wire_chirho,
            holder_node_id_chirho,
        )?;
        Ok(Some((receipt_chirho, wire_chirho)))
    }

    fn require_local_source_head_on_canonical_chain_chirho(
        local_tail_chirho: &LedgerAppendMirrorTailChirho,
        local_receipt_chirho: &LedgerMirrorRecoveryHeadReceiptChirho,
        local_source_chirho: &dyn LedgerMirrorPrefixSourceChirho,
    ) -> Result<()> {
        let identity_chirho = LosingSuffixJournalIdentityChirho::new_chirho(DigestChirho(
            local_tail_chirho.journal_genesis_digest_chirho().0.clone(),
        ));
        let frozen_tail_chirho = LosingSuffixCoordinateChirho::new_chirho(
            local_tail_chirho.tail_seq_chirho(),
            DigestChirho(local_tail_chirho.tail_record_digest_chirho().0.clone()),
        );
        let exact_anchor_chirho = LosingSuffixCoordinateChirho::new_chirho(
            local_receipt_chirho.tail_seq_chirho(),
            DigestChirho(local_receipt_chirho.tail_record_digest_chirho().to_string()),
        );
        // This is a cold recovery check after the canonical journal has full-verified. Each page
        // and its memory stay bounded; total work is scoped to the exact tail-to-holder interval.
        let mut cursor_chirho = None;
        loop {
            let mut request_chirho = LosingSuffixPageRequestChirho::new_chirho(
                identity_chirho.clone(),
                frozen_tail_chirho.clone(),
                exact_anchor_chirho.clone(),
                PREFIX_PAGE_MAX_RECORDS_CHIRHO,
                512 * 1024,
            );
            if let Some(cursor_value_chirho) = cursor_chirho.take() {
                request_chirho = request_chirho.with_cursor_chirho(cursor_value_chirho);
            }
            let page_chirho = match local_source_chirho
                .read_verified_losing_suffix_page_chirho(&request_chirho)
            {
                Ok(page_chirho) => page_chirho,
                Err(
                    LosingSuffixReadErrorChirho::AnchorDigestMismatchChirho
                    | LosingSuffixReadErrorChirho::AnchorDigestMismatchAtFrozenTailChirho,
                ) => {
                    bail!("LedgerMirrorLocalRecoveryHeadCanonicalHistoryDivergenceRefusedChirho")
                }
                Err(error_chirho) => {
                    bail!(
                        "LedgerMirrorLocalRecoveryHeadCanonicalHistoryReadRefusedChirho: {error_chirho:?}"
                    )
                }
            };
            if page_chirho.reached_anchor_chirho() {
                return Ok(());
            }
            if page_chirho.records_newest_first_chirho().is_empty() {
                bail!("LedgerMirrorLocalRecoveryHeadCanonicalHistoryNoProgressChirho");
            }
            cursor_chirho = Some(page_chirho.next_cursor_chirho().cloned().ok_or_else(|| {
                anyhow::anyhow!("LedgerMirrorLocalRecoveryHeadCanonicalHistoryCursorMissingChirho")
            })?);
        }
    }

    fn select_candidate_chirho(
        &self,
        local_tail_chirho: &LedgerAppendMirrorTailChirho,
        local_source_chirho: &dyn LedgerMirrorPrefixSourceChirho,
    ) -> Result<Option<LedgerMirrorRecoveryCandidateChirho>> {
        let joined_chirho = self.current_leader_view_chirho()?;
        let current_assigned_chirho = self
            .placement_chirho
            .assigned_nodes_chirho()
            .iter()
            .map(|node_chirho| node_chirho.node_id_chirho.clone())
            .collect::<Vec<_>>();
        let local_source_head_chirho = self
            .follower_store_chirho
            .load_recovery_source_head_chirho()?;
        let local_source_evidence_chirho =
            if let Some(local_source_head_chirho) = local_source_head_chirho {
                let local_receipt_chirho =
                    LedgerMirrorRecoveryHeadReceiptChirho::sign_from_source_head_chirho(
                        &local_source_head_chirho,
                        &self.sign_root_chirho,
                    )?;
                if !self.recovery_assignment_matches_chirho(
                    local_receipt_chirho.assignment_digest_chirho(),
                ) {
                    bail!("LedgerMirrorLocalRecoveryHeadAssignmentBindingRefusedChirho");
                }
                if local_receipt_chirho.assigned_node_ids_chirho().as_slice()
                    != current_assigned_chirho.as_slice()
                    || local_receipt_chirho.consistency_group_digest_chirho()
                        != joined_chirho
                            .view_chirho()
                            .consistency_group_digest_chirho()
                    || local_receipt_chirho.holder_node_id_chirho() != self.local_node_id_chirho
                    || local_receipt_chirho.cluster_id_chirho()
                        != local_tail_chirho.cluster_id_chirho().0
                    || local_receipt_chirho.journal_genesis_digest_chirho()
                        != local_tail_chirho.journal_genesis_digest_chirho().0
                {
                    bail!("LedgerMirrorLocalRecoveryHeadBindingRefusedChirho");
                }
                if local_receipt_chirho.tail_seq_chirho() < local_tail_chirho.tail_seq_chirho() {
                    // A strictly older local follower head may be excluded only after the already
                    // full-verified canonical journal proves that exact coordinate is on its chain.
                    // Equal and newer heads remain in the historical-pair path, where mixed provenance
                    // or same-sequence divergence still refuses instead of being hidden as staleness.
                    Self::require_local_source_head_on_canonical_chain_chirho(
                        local_tail_chirho,
                        &local_receipt_chirho,
                        local_source_chirho,
                    )?;
                    None
                } else {
                    Some((
                        local_receipt_chirho.clone(),
                        local_receipt_chirho.to_wire_bytes_chirho()?,
                    ))
                }
            } else {
                None
            };
        let evidence_chirho =
            if let Some((local_receipt_chirho, local_wire_chirho)) = local_source_evidence_chirho {
                let remote_holders_chirho = local_receipt_chirho
                    .assigned_node_ids_chirho()
                    .iter()
                    .filter(|node_id_chirho| {
                        *node_id_chirho != local_receipt_chirho.historical_leader_node_id_chirho()
                            && *node_id_chirho != &self.local_node_id_chirho
                    })
                    .collect::<Vec<_>>();
                let [remote_holder_chirho] = remote_holders_chirho.as_slice() else {
                    bail!("LedgerMirrorRemoteHistoricalHolderMissingChirho");
                };
                let remote_chirho = self
                    .read_remote_recovery_head_chirho(&joined_chirho, remote_holder_chirho)?
                    .ok_or_else(|| anyhow::anyhow!("LedgerMirrorRecoveryHeadUnavailableChirho"))?;
                vec![(local_receipt_chirho, local_wire_chirho), remote_chirho]
            } else {
                let remote_holders_chirho = current_assigned_chirho
                    .iter()
                    .filter(|node_id_chirho| *node_id_chirho != &self.local_node_id_chirho)
                    .collect::<Vec<_>>();
                let [first_holder_chirho, second_holder_chirho] = remote_holders_chirho.as_slice()
                else {
                    bail!("LedgerMirrorRemoteHistoricalHolderPopulationRefusedChirho");
                };
                let first_chirho =
                    self.read_remote_recovery_head_chirho(&joined_chirho, first_holder_chirho)?;
                let second_chirho =
                    self.read_remote_recovery_head_chirho(&joined_chirho, second_holder_chirho)?;
                match (first_chirho, second_chirho) {
                    (None, None) => return Ok(None),
                    (Some(first_chirho), Some(second_chirho)) => {
                        vec![first_chirho, second_chirho]
                    }
                    _ => bail!("LedgerMirrorRecoveryHeadUnavailableChirho"),
                }
            };
        let [(first_receipt_chirho, first_wire_chirho), (second_receipt_chirho, second_wire_chirho)] =
            evidence_chirho.as_slice()
        else {
            bail!("LedgerMirrorRecoveryHeadPopulationRefusedChirho");
        };
        let pair_chirho = VerifiedLedgerMirrorRecoveryHeadPairChirho::join_chirho(
            first_receipt_chirho.clone(),
            second_receipt_chirho.clone(),
        )?;
        let [pair_first_chirho, pair_second_chirho] = pair_chirho.receipts_chirho();
        let wire_for_receipt_chirho = |receipt_chirho: &LedgerMirrorRecoveryHeadReceiptChirho| {
            if receipt_chirho.holder_node_id_chirho()
                == first_receipt_chirho.holder_node_id_chirho()
            {
                first_wire_chirho.clone()
            } else {
                second_wire_chirho.clone()
            }
        };
        let holder_receipt_wires_chirho = [
            wire_for_receipt_chirho(pair_first_chirho),
            wire_for_receipt_chirho(pair_second_chirho),
        ];
        let first_chirho = &pair_chirho.receipts_chirho()[0];
        if !self.recovery_assignment_matches_chirho(first_chirho.assignment_digest_chirho()) {
            bail!("LedgerMirrorRecoveryHeadAssignmentBindingRefusedChirho");
        }
        if first_chirho.assigned_node_ids_chirho().as_slice() != current_assigned_chirho.as_slice()
            || first_chirho.consistency_group_digest_chirho()
                != joined_chirho
                    .view_chirho()
                    .consistency_group_digest_chirho()
            || first_chirho.cluster_id_chirho() != local_tail_chirho.cluster_id_chirho().0
            || first_chirho.journal_genesis_digest_chirho()
                != local_tail_chirho.journal_genesis_digest_chirho().0
        {
            bail!("LedgerMirrorRecoveryHeadBindingRefusedChirho");
        }
        let current_after_chirho = self.current_leader_view_chirho()?;
        if current_after_chirho.term_chirho() != joined_chirho.term_chirho()
            || current_after_chirho.view_chirho().view_digest_chirho()
                != joined_chirho.view_chirho().view_digest_chirho()
        {
            bail!("LedgerMirrorRecoveryAuthorityChangedAfterHeadReadChirho");
        }
        if pair_chirho.tail_seq_chirho() < local_tail_chirho.tail_seq_chirho()
            || (pair_chirho.tail_seq_chirho() == local_tail_chirho.tail_seq_chirho()
                && pair_chirho.tail_record_digest_chirho()
                    != local_tail_chirho.tail_record_digest_chirho().0)
        {
            bail!("LedgerMirrorRecoveryHeadBehindOrDivergentChirho");
        }
        if pair_chirho.tail_seq_chirho() == local_tail_chirho.tail_seq_chirho() {
            return Ok(None);
        }
        LedgerMirrorRecoveryCandidateChirho::from_port_evidence_chirho(
            LedgerMirrorRecoveryCandidateInputChirho {
                consistency_group_digest_chirho:
                    RawCanonicalGroupIdDigestChirho::from_mirror_evidence_chirho(
                        first_chirho.consistency_group_digest_chirho().to_string(),
                    )?,
                assignment_digest_chirho: first_chirho.assignment_digest_chirho().to_string(),
                historical_leader_node_id_chirho: first_chirho
                    .historical_leader_node_id_chirho()
                    .to_string(),
                holder_node_ids_chirho: [
                    pair_chirho.receipts_chirho()[0]
                        .holder_node_id_chirho()
                        .to_string(),
                    pair_chirho.receipts_chirho()[1]
                        .holder_node_id_chirho()
                        .to_string(),
                ],
                historical_term_chirho: first_chirho.historical_term_chirho(),
                historical_membership_view_digest_chirho: first_chirho
                    .historical_membership_view_digest_chirho()
                    .to_string(),
                cluster_id_chirho: first_chirho.cluster_id_chirho().to_string(),
                journal_genesis_digest_chirho: pair_chirho
                    .journal_genesis_digest_chirho()
                    .to_string(),
                tail_seq_chirho: pair_chirho.tail_seq_chirho(),
                tail_record_digest_chirho: pair_chirho.tail_record_digest_chirho().to_string(),
                tail_epoch_chirho: first_chirho.tail_epoch_chirho(),
                tail_hlc_chirho: cairn_ledger_model_chirho::record_chirho::HlcChirho {
                    physical_ms_chirho: first_chirho.tail_hlc_physical_ms_chirho(),
                    logical_chirho: first_chirho.tail_hlc_logical_chirho(),
                },
                current_term_chirho: joined_chirho.term_chirho(),
                current_membership_view_digest_chirho: joined_chirho
                    .view_chirho()
                    .view_digest_chirho(),
                holder_receipt_digests_chirho: [
                    pair_first_chirho.receipt_digest_chirho().to_string(),
                    pair_second_chirho.receipt_digest_chirho().to_string(),
                ],
                holder_receipt_wires_chirho,
            },
        )
        .map(Some)
        .map_err(Into::into)
    }

    fn revalidate_candidate_chirho(
        &self,
        candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
    ) -> Result<()> {
        let joined_chirho = self.current_leader_view_chirho()?;
        if !self.recovery_assignment_matches_chirho(candidate_chirho.assignment_digest_chirho()) {
            bail!("LedgerMirrorRecoveryCandidateAssignmentExpiredChirho");
        }
        if candidate_chirho
            .consistency_group_digest_chirho()
            .as_str_chirho()
            != joined_chirho
                .view_chirho()
                .consistency_group_digest_chirho()
            || candidate_chirho.current_term_chirho() != joined_chirho.term_chirho()
            || candidate_chirho.current_membership_view_digest_chirho()
                != joined_chirho.view_chirho().view_digest_chirho()
        {
            bail!("LedgerMirrorRecoveryCandidateAuthorityExpiredChirho");
        }
        Ok(())
    }

    fn ensure_prefix_bootstrapped_chirho(
        &self,
        source_tail_chirho: &LedgerAppendMirrorTailChirho,
        source_chirho: &dyn LedgerMirrorPrefixSourceChirho,
    ) -> Result<()> {
        if source_tail_chirho.tail_seq_chirho() == 0 {
            return Ok(());
        }
        let canonical_genesis_line_chirho = source_chirho.canonical_genesis_line_chirho()?;
        let LedgerJournalLineChirho::GenesisChirho(genesis_chirho) =
            parse_canonical_ledger_journal_line_chirho(&canonical_genesis_line_chirho)
                .map_err(|_| anyhow::anyhow!("LedgerMirrorPrefixGenesisParseRefusedChirho"))?
        else {
            bail!("LedgerMirrorPrefixGenesisKindRefusedChirho");
        };
        if genesis_chirho.cluster_id_chirho != *source_tail_chirho.cluster_id_chirho()
            || stored_line_digest_chirho(&canonical_genesis_line_chirho)
                != *source_tail_chirho.journal_genesis_digest_chirho()
        {
            bail!("LedgerMirrorPrefixGenesisBindingRefusedChirho");
        }
        let joined_chirho = self.current_leader_view_chirho()?;
        self.verify_source_tail_chirho(source_tail_chirho, source_chirho)?;

        let mut first_hasher_chirho = LedgerMirrorDenseChainHasherChirho::new_chirho();
        let mut tail_record_chirho = None;
        self.visit_verified_prefix_pages_chirho(
            source_tail_chirho,
            source_chirho,
            |_, records_chirho| {
                for record_chirho in records_chirho {
                    if tail_record_chirho.is_none() {
                        tail_record_chirho = Some(record_chirho.clone());
                    }
                    first_hasher_chirho.update_chirho(record_chirho)?;
                }
                Ok(())
            },
        )?;
        let (record_count_chirho, dense_chain_digest_chirho) = first_hasher_chirho.finish_chirho();
        let tail_record_chirho = tail_record_chirho
            .ok_or_else(|| anyhow::anyhow!("LedgerMirrorPrefixTailRecordUnavailableChirho"))?;
        if record_count_chirho != source_tail_chirho.tail_seq_chirho()
            || tail_record_chirho.record_seq_chirho != source_tail_chirho.tail_seq_chirho()
            || tail_record_chirho.record_digest_chirho
                != source_tail_chirho.tail_record_digest_chirho().0
            || tail_record_chirho.record_hlc_physical_ms_chirho
                != source_tail_chirho.tail_hlc_chirho().physical_ms_chirho
            || tail_record_chirho.record_hlc_logical_chirho
                != source_tail_chirho.tail_hlc_chirho().logical_chirho
        {
            bail!("LedgerMirrorPrefixSourceTailBindingRefusedChirho");
        }
        self.verify_source_tail_chirho(source_tail_chirho, source_chirho)?;
        let joined_after_first_pass_chirho = self.current_leader_view_chirho()?;
        verify_same_current_view_chirho(&joined_chirho, &joined_after_first_pass_chirho)?;

        let assigned_node_ids_chirho: [String; 3] = self
            .placement_chirho
            .assigned_nodes_chirho()
            .iter()
            .map(|node_chirho| node_chirho.node_id_chirho.clone())
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| anyhow::anyhow!("LedgerMirrorAssignedNodePopulationRefusedChirho"))?;
        let manifest_chirho = LedgerMirrorVerifiedPrefixManifestChirho::sign_chirho(
            LedgerMirrorVerifiedPrefixManifestInputChirho {
                origin_leader_node_id_chirho: self.local_node_id_chirho.clone(),
                consistency_group_digest_chirho: joined_chirho
                    .view_chirho()
                    .consistency_group_digest_chirho()
                    .to_string(),
                assignment_digest_chirho: self
                    .placement_chirho
                    .assignment_digest_chirho()
                    .to_string(),
                assigned_node_ids_chirho,
                expected_term_chirho: joined_chirho.term_chirho(),
                membership_view_digest_chirho: joined_chirho.view_chirho().view_digest_chirho(),
                cluster_id_chirho: source_tail_chirho.cluster_id_chirho().0.clone(),
                journal_genesis_digest_chirho: source_tail_chirho
                    .journal_genesis_digest_chirho()
                    .0
                    .clone(),
                tail_seq_chirho: tail_record_chirho.record_seq_chirho,
                tail_record_digest_chirho: tail_record_chirho.record_digest_chirho.clone(),
                tail_epoch_chirho: tail_record_chirho.record_epoch_chirho,
                tail_hlc_physical_ms_chirho: tail_record_chirho.record_hlc_physical_ms_chirho,
                tail_hlc_logical_chirho: tail_record_chirho.record_hlc_logical_chirho,
                record_count_chirho,
                dense_chain_digest_chirho,
            },
            &self.sign_root_chirho,
        )?;
        let holder_set_chirho = MirrorHolderSetChirho::select_chirho(
            joined_chirho.view_chirho(),
            &self.local_node_id_chirho,
            &self.residency_chirho,
        )?;
        let holder_node_ids_chirho = holder_set_chirho
            .mirror_holders_chirho()
            .iter()
            .map(|holder_chirho| holder_chirho.node_id_chirho().to_string())
            .collect::<Vec<_>>();
        let mut needs_transfer_chirho = BTreeSet::new();
        for holder_node_id_chirho in &holder_node_ids_chirho {
            if !self.directory_chirho.begin_verified_prefix_chirho(
                holder_node_id_chirho,
                &manifest_chirho,
                &self.agent_chirho,
            )? {
                needs_transfer_chirho.insert(holder_node_id_chirho.clone());
            }
        }

        if !needs_transfer_chirho.is_empty() {
            let mut second_hasher_chirho = LedgerMirrorDenseChainHasherChirho::new_chirho();
            self.visit_verified_prefix_pages_chirho(
                source_tail_chirho,
                source_chirho,
                |page_index_chirho, records_chirho| {
                    for record_chirho in records_chirho {
                        second_hasher_chirho.update_chirho(record_chirho)?;
                    }
                    let page_chirho = LedgerMirrorVerifiedPrefixPageChirho::new_chirho(
                        manifest_chirho.manifest_digest_chirho().to_string(),
                        page_index_chirho,
                        records_chirho.to_vec(),
                    )?;
                    for holder_node_id_chirho in &needs_transfer_chirho {
                        self.directory_chirho.send_verified_prefix_page_chirho(
                            holder_node_id_chirho,
                            &page_chirho,
                            &self.agent_chirho,
                        )?;
                    }
                    Ok(())
                },
            )?;
            let second_closure_chirho = second_hasher_chirho.finish_chirho();
            if second_closure_chirho
                != (
                    manifest_chirho.record_count_chirho(),
                    manifest_chirho.dense_chain_digest_chirho().to_string(),
                )
            {
                bail!("LedgerMirrorPrefixSecondPassDivergenceRefusedChirho");
            }
        }

        self.verify_source_tail_chirho(source_tail_chirho, source_chirho)?;
        let joined_before_seal_chirho = self.current_leader_view_chirho()?;
        verify_same_current_view_chirho(&joined_chirho, &joined_before_seal_chirho)?;
        for holder_node_id_chirho in &needs_transfer_chirho {
            self.directory_chirho.seal_verified_prefix_chirho(
                holder_node_id_chirho,
                &manifest_chirho,
                &self.agent_chirho,
            )?;
        }
        self.verify_current_holder_prefix_population_chirho(
            &joined_chirho,
            &manifest_chirho,
            &holder_node_ids_chirho,
        )?;
        let joined_after_chirho = self.current_leader_view_chirho()?;
        verify_same_current_view_chirho(&joined_chirho, &joined_after_chirho)
    }

    fn visit_verified_prefix_pages_chirho(
        &self,
        source_tail_chirho: &LedgerAppendMirrorTailChirho,
        source_chirho: &dyn LedgerMirrorPrefixSourceChirho,
        mut visit_chirho: impl FnMut(
            u64,
            &[crate::family_chirho::LedgerMirrorRecordChirho],
        ) -> Result<()>,
    ) -> Result<()> {
        let identity_chirho = LosingSuffixJournalIdentityChirho::new_chirho(DigestChirho(
            source_tail_chirho.journal_genesis_digest_chirho().0.clone(),
        ));
        let frozen_tail_chirho = LosingSuffixCoordinateChirho::new_chirho(
            source_tail_chirho.tail_seq_chirho(),
            DigestChirho(source_tail_chirho.tail_record_digest_chirho().0.clone()),
        );
        let anchor_chirho = LosingSuffixCoordinateChirho::new_chirho(
            0,
            DigestChirho(source_tail_chirho.journal_genesis_digest_chirho().0.clone()),
        );
        let mut cursor_chirho = None;
        let mut page_index_chirho = 0u64;
        loop {
            let mut request_chirho = LosingSuffixPageRequestChirho::new_chirho(
                identity_chirho.clone(),
                frozen_tail_chirho.clone(),
                anchor_chirho.clone(),
                PREFIX_PAGE_MAX_RECORDS_CHIRHO,
                512 * 1024,
            );
            if let Some(cursor_value_chirho) = cursor_chirho.take() {
                request_chirho = request_chirho.with_cursor_chirho(cursor_value_chirho);
            }
            let page_chirho = source_chirho
                .read_verified_losing_suffix_page_chirho(&request_chirho)
                .map_err(|error_chirho| {
                    anyhow::anyhow!("LedgerMirrorPrefixSourceReadRefusedChirho: {error_chirho:?}")
                })?;
            let records_chirho = page_chirho
                .records_newest_first_chirho()
                .iter()
                .map(|record_chirho| {
                    crate::family_chirho::LedgerMirrorRecordChirho::from_verified_record_chirho(
                        &source_tail_chirho.cluster_id_chirho().0,
                        &source_tail_chirho.journal_genesis_digest_chirho().0,
                        record_chirho,
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            if records_chirho.is_empty() && !page_chirho.reached_anchor_chirho() {
                bail!("LedgerMirrorPrefixTraversalNoProgressChirho");
            }
            if !records_chirho.is_empty() {
                visit_chirho(page_index_chirho, &records_chirho)?;
                page_index_chirho = page_index_chirho
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("LedgerMirrorPrefixPageIndexExhaustedChirho"))?;
            }
            if page_chirho.reached_anchor_chirho() {
                break;
            }
            cursor_chirho = Some(
                page_chirho
                    .next_cursor_chirho()
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("LedgerMirrorPrefixCursorMissingChirho"))?,
            );
        }
        Ok(())
    }

    fn verify_source_tail_chirho(
        &self,
        source_tail_chirho: &LedgerAppendMirrorTailChirho,
        source_chirho: &dyn LedgerMirrorPrefixSourceChirho,
    ) -> Result<VerifiedLosingJournalTailChirho> {
        let verified_chirho = source_chirho
            .revalidate_current_losing_tail_chirho()
            .map_err(|error_chirho| {
                anyhow::anyhow!("LedgerMirrorPrefixSourceTailReadRefusedChirho: {error_chirho:?}")
            })?;
        if verified_chirho.identity_chirho().genesis_digest_chirho()
            != source_tail_chirho.journal_genesis_digest_chirho()
            || verified_chirho.coordinate_chirho().seq_chirho()
                != source_tail_chirho.tail_seq_chirho()
            || verified_chirho.coordinate_chirho().record_digest_chirho()
                != source_tail_chirho.tail_record_digest_chirho()
        {
            bail!("LedgerMirrorPrefixSourceTailChangedChirho");
        }
        Ok(verified_chirho)
    }

    pub(super) fn verify_current_holder_prefix_population_chirho(
        &self,
        joined_chirho: &cairn_mirror_chirho::JoinedMirrorViewChirho,
        manifest_chirho: &LedgerMirrorVerifiedPrefixManifestChirho,
        holder_node_ids_chirho: &[String],
    ) -> Result<()> {
        let mut receipts_chirho = Vec::with_capacity(2);
        for holder_node_id_chirho in holder_node_ids_chirho {
            // Keep construction above the bounded read retry for the same frozen-authority guarantee
            // used by ordinary recovery selection.
            let request_chirho = LedgerMirrorRecoveryHeadRequestChirho::sign_chirho(
                LedgerMirrorRecoveryHeadRequestInputChirho {
                    requester_node_id_chirho: self.local_node_id_chirho.clone(),
                    target_node_id_chirho: holder_node_id_chirho.clone(),
                    consistency_group_digest_chirho: joined_chirho
                        .view_chirho()
                        .consistency_group_digest_chirho()
                        .to_string(),
                    assignment_digest_chirho: self
                        .placement_chirho
                        .assignment_digest_chirho()
                        .to_string(),
                    expected_term_chirho: joined_chirho.term_chirho(),
                    membership_view_digest_chirho: joined_chirho.view_chirho().view_digest_chirho(),
                },
                &self.sign_root_chirho,
            )?;
            let wire_chirho = self
                .directory_chirho
                .read_recovery_head_chirho(
                    holder_node_id_chirho,
                    &request_chirho,
                    &self.agent_chirho,
                )?
                .ok_or_else(|| anyhow::anyhow!("LedgerMirrorBootstrapHeadUnavailableChirho"))?;
            receipts_chirho.push((
                LedgerMirrorRecoveryHeadReceiptChirho::decode_and_verify_chirho(
                    &wire_chirho,
                    holder_node_id_chirho,
                )?,
                wire_chirho,
            ));
        }
        let [first_chirho, second_chirho] = receipts_chirho.as_slice() else {
            bail!("LedgerMirrorBootstrapHolderPopulationRefusedChirho");
        };
        require_common_bootstrap_pair_chirho(&first_chirho.0, &second_chirho.0)?;
        let assigned_node_ids_chirho: [String; 3] = self
            .placement_chirho
            .assigned_nodes_chirho()
            .iter()
            .map(|node_chirho| node_chirho.node_id_chirho.clone())
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| anyhow::anyhow!("LedgerMirrorAssignedNodePopulationRefusedChirho"))?;
        for receipt_chirho in [first_chirho.0.clone(), second_chirho.0.clone()] {
            let provenance_matches_chirho = match receipt_chirho.source_head_kind_chirho() {
                RECOVERY_SOURCE_LIVE_CHIRHO => {
                    receipt_chirho.source_manifest_digest_chirho().is_none()
                }
                RECOVERY_SOURCE_BOOTSTRAP_CHIRHO => {
                    receipt_chirho.historical_leader_node_id_chirho() == self.local_node_id_chirho
                        && receipt_chirho.source_manifest_digest_chirho().is_some()
                        && receipt_chirho.historical_term_chirho() <= joined_chirho.term_chirho()
                }
                _ => false,
            };
            // Source selection deliberately prefers an equal-sequence live high-water over a
            // bootstrap head. A current holder can therefore prove the exact newly bootstrapped
            // prefix through its predecessor-bound live head until adoption advances that head.
            if !self.recovery_assignment_matches_chirho(receipt_chirho.assignment_digest_chirho()) {
                bail!("LedgerMirrorCurrentHolderPrefixAssignmentBindingRefusedChirho");
            }
            if receipt_chirho.consistency_group_digest_chirho()
                != joined_chirho
                    .view_chirho()
                    .consistency_group_digest_chirho()
                || receipt_chirho.assigned_node_ids_chirho() != &assigned_node_ids_chirho
                || receipt_chirho.cluster_id_chirho() != manifest_chirho.cluster_id_chirho()
                || receipt_chirho.journal_genesis_digest_chirho()
                    != manifest_chirho.journal_genesis_digest_chirho()
                || receipt_chirho.tail_seq_chirho() != manifest_chirho.tail_seq_chirho()
                || receipt_chirho.tail_record_digest_chirho()
                    != manifest_chirho.tail_record_digest_chirho()
                || receipt_chirho.tail_epoch_chirho() != manifest_chirho.tail_epoch_chirho()
                || receipt_chirho.tail_hlc_physical_ms_chirho()
                    != manifest_chirho.tail_hlc_physical_ms_chirho()
                || receipt_chirho.tail_hlc_logical_chirho()
                    != manifest_chirho.tail_hlc_logical_chirho()
                || !provenance_matches_chirho
            {
                bail!("LedgerMirrorCurrentHolderPrefixBindingRefusedChirho");
            }
        }
        Ok(())
    }
}

impl LedgerMirrorRecoveryPortChirho for ProductionLedgerMirrorRecoveryPortChirho {
    fn select_recovery_candidate_chirho(
        &self,
        local_tail_chirho: &LedgerAppendMirrorTailChirho,
        local_source_chirho: &dyn LedgerMirrorPrefixSourceChirho,
    ) -> Result<Option<LedgerMirrorRecoveryCandidateChirho>, LedgerMirrorRecoveryPortErrorChirho>
    {
        let _guard_chirho = self
            .operation_lock_chirho
            .lock()
            .map_err(|_| port_error_chirho("LedgerMirrorRecoveryPortPoisonedChirho"))?;
        self.select_candidate_chirho(local_tail_chirho, local_source_chirho)
            .map_err(port_error_from_anyhow_chirho)
    }

    fn revalidate_recovery_authority_chirho(
        &self,
        candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
    ) -> Result<(), LedgerMirrorRecoveryPortErrorChirho> {
        self.revalidate_candidate_chirho(candidate_chirho)
            .map_err(port_error_from_anyhow_chirho)
    }

    fn read_recovery_record_chirho(
        &self,
        candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
        seq_chirho: u64,
        record_digest_chirho: &str,
    ) -> Result<Vec<u8>, LedgerMirrorRecoveryPortErrorChirho> {
        if !self.recovery_assignment_matches_chirho(candidate_chirho.assignment_digest_chirho()) {
            return Err(port_error_chirho(
                "LedgerMirrorRecoveryRecordAssignmentBindingRefusedChirho",
            ));
        }
        if candidate_chirho.cluster_id_chirho().is_empty()
            || seq_chirho == 0
            || seq_chirho > candidate_chirho.tail_seq_chirho()
        {
            return Err(port_error_chirho(
                "LedgerMirrorRecoveryRecordRequestRefusedChirho",
            ));
        }
        self.follower_store_chirho
            .read_recovery_record_chirho(
                candidate_chirho.cluster_id_chirho(),
                candidate_chirho.journal_genesis_digest_chirho(),
                seq_chirho,
                record_digest_chirho,
            )
            .map_err(port_error_from_anyhow_chirho)
    }

    fn ensure_verified_prefix_bootstrapped_chirho(
        &self,
        source_tail_chirho: &LedgerAppendMirrorTailChirho,
        source_chirho: &dyn LedgerMirrorPrefixSourceChirho,
    ) -> Result<(), LedgerMirrorRecoveryPortErrorChirho> {
        let _guard_chirho = self
            .operation_lock_chirho
            .lock()
            .map_err(|_| port_error_chirho("LedgerMirrorRecoveryPortPoisonedChirho"))?;
        self.ensure_prefix_bootstrapped_chirho(source_tail_chirho, source_chirho)
            .map_err(port_error_from_anyhow_chirho)
    }
}

impl LedgerMirrorOrdinaryTermAcceptanceEvidenceSourceChirho
    for ProductionLedgerMirrorRecoveryPortChirho
{
    /// Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.
    fn read_ordinary_term_acceptance_receipts_chirho(
        &self,
        challenge_chirho: &LedgerMirrorOrdinaryTermAcceptanceChallengeChirho,
        local_tail_chirho: &LedgerAppendMirrorTailChirho,
    ) -> Result<[Vec<u8>; 2], LedgerMirrorRecoveryPortErrorChirho> {
        let _operation_guard_chirho = self.operation_lock_chirho.lock().map_err(|_| {
            LedgerMirrorRecoveryPortErrorChirho::new_chirho(
                "LedgerMirrorOrdinaryTermAcceptanceOperationPoisonedChirho",
            )
        })?;
        let joined_chirho = self.current_leader_view_chirho().map_err(|error_chirho| {
            LedgerMirrorRecoveryPortErrorChirho::new_chirho(error_chirho.to_string())
        })?;
        let assigned_node_ids_chirho: [String; 3] = self
            .placement_chirho
            .assigned_nodes_chirho()
            .iter()
            .map(|node_chirho| node_chirho.node_id_chirho.clone())
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| {
                LedgerMirrorRecoveryPortErrorChirho::new_chirho(
                    "LedgerMirrorAssignedNodePopulationRefusedChirho",
                )
            })?;
        let holder_set_chirho = MirrorHolderSetChirho::select_chirho(
            joined_chirho.view_chirho(),
            &self.local_node_id_chirho,
            &self.residency_chirho,
        )
        .map_err(|error_chirho| {
            LedgerMirrorRecoveryPortErrorChirho::new_chirho(error_chirho.to_string())
        })?;
        let [first_holder_chirho, second_holder_chirho] = holder_set_chirho.mirror_holders_chirho();
        let read_holder_chirho = |holder_node_id_chirho: &str| {
            let request_chirho = LedgerMirrorOrdinaryTermAcceptanceRequestChirho::sign_chirho(
                LedgerMirrorOrdinaryTermAcceptanceRequestInputChirho {
                    challenge_nonce_hex_chirho: challenge_chirho.as_str_chirho().to_owned(),
                    requester_node_id_chirho: self.local_node_id_chirho.clone(),
                    target_node_id_chirho: holder_node_id_chirho.to_owned(),
                    consistency_group_digest_chirho: joined_chirho
                        .view_chirho()
                        .consistency_group_digest_chirho()
                        .to_owned(),
                    assignment_digest_chirho: self
                        .placement_chirho
                        .assignment_digest_chirho()
                        .to_owned(),
                    assigned_node_ids_chirho: assigned_node_ids_chirho.clone(),
                    expected_term_chirho: joined_chirho.term_chirho(),
                    membership_view_digest_chirho: joined_chirho.view_chirho().view_digest_chirho(),
                    cluster_id_chirho: local_tail_chirho.cluster_id_chirho().0.clone(),
                    journal_genesis_digest_chirho: local_tail_chirho
                        .journal_genesis_digest_chirho()
                        .0
                        .clone(),
                    tail_seq_chirho: local_tail_chirho.tail_seq_chirho(),
                    tail_record_digest_chirho: local_tail_chirho
                        .tail_record_digest_chirho()
                        .0
                        .clone(),
                    tail_epoch_chirho: local_tail_chirho.tail_record_epoch_chirho(),
                    tail_hlc_physical_ms_chirho: local_tail_chirho
                        .tail_hlc_chirho()
                        .physical_ms_chirho,
                    tail_hlc_logical_chirho: local_tail_chirho.tail_hlc_chirho().logical_chirho,
                },
                &self.sign_root_chirho,
            )
            .map_err(|error_chirho| {
                LedgerMirrorRecoveryPortErrorChirho::new_chirho(error_chirho.to_string())
            })?;
            self.directory_chirho
                .read_ordinary_term_acceptance_receipt_chirho(
                    holder_node_id_chirho,
                    &request_chirho,
                    &self.agent_chirho,
                )
                .map_err(|error_chirho| {
                    LedgerMirrorRecoveryPortErrorChirho::new_chirho(error_chirho.to_string())
                })
        };
        let first_wire_chirho = read_holder_chirho(first_holder_chirho.node_id_chirho())?;
        let second_wire_chirho = read_holder_chirho(second_holder_chirho.node_id_chirho())?;
        let after_chirho = self.current_leader_view_chirho().map_err(|error_chirho| {
            LedgerMirrorRecoveryPortErrorChirho::new_chirho(error_chirho.to_string())
        })?;
        verify_same_current_view_chirho(&joined_chirho, &after_chirho).map_err(|_| {
            LedgerMirrorRecoveryPortErrorChirho::new_chirho(
                "LedgerMirrorOrdinaryTermAuthorityChangedAfterReceiptReadChirho",
            )
        })?;
        Ok([first_wire_chirho, second_wire_chirho])
    }
}

fn verify_same_current_view_chirho(
    before_chirho: &cairn_mirror_chirho::JoinedMirrorViewChirho,
    after_chirho: &cairn_mirror_chirho::JoinedMirrorViewChirho,
) -> Result<()> {
    if before_chirho.term_chirho() != after_chirho.term_chirho()
        || before_chirho.view_chirho().view_digest_chirho()
            != after_chirho.view_chirho().view_digest_chirho()
        || before_chirho.elected_leader_node_id_chirho()
            != after_chirho.elected_leader_node_id_chirho()
    {
        bail!("LedgerMirrorPrefixAuthorityChangedChirho");
    }
    Ok(())
}

fn port_error_from_anyhow_chirho(
    error_chirho: anyhow::Error,
) -> LedgerMirrorRecoveryPortErrorChirho {
    port_error_chirho(error_chirho.to_string())
}

fn port_error_chirho(detail_chirho: impl Into<String>) -> LedgerMirrorRecoveryPortErrorChirho {
    LedgerMirrorRecoveryPortErrorChirho::new_chirho(detail_chirho)
}
