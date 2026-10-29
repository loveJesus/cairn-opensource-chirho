// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

impl<'ports_chirho> ResidentLedgerAuthorityChirho<'ports_chirho> {
    /// Append through the retained descriptor namespace while one local generation remains sealed.
    ///
    /// The reviewed H3 activation capsule is the only production caller and constructs the request
    /// from a signed typed intent. The method accepts no callback, elector, storage adapter, or
    /// caller-selected path.
    pub fn append_preactivation_chirho(
        &mut self,
        _permit_chirho: &ResidentLedgerAppendPermitChirho,
        request_chirho: AppendRequestChirho,
    ) -> Result<ResidentLedgerAppendReceiptChirho, ResidentLedgerAuthorityRefusalChirho> {
        self.append_with_current_fence_chirho(
            ResidentLedgerMutationChirho::ReviewedActivationChirho { request_chirho },
        )
    }

    pub(crate) fn record_effect_hold_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        verifier_chirho: &dyn EffectIntentSignerPortChirho,
    ) -> Result<ResidentLedgerAppendReceiptChirho, ResidentLedgerAuthorityRefusalChirho> {
        self.append_with_current_fence_chirho(ResidentLedgerMutationChirho::EffectHoldChirho {
            canonical_intent_line_chirho,
            verifier_chirho,
        })
    }

    pub(crate) fn record_effect_compensation_hold_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        verifier_chirho: &dyn EffectIntentSignerPortChirho,
        authorization_chirho: &VerifiedEffectCompensationChirho,
    ) -> Result<ResidentLedgerAppendReceiptChirho, ResidentLedgerAuthorityRefusalChirho> {
        self.append_with_current_fence_chirho(
            ResidentLedgerMutationChirho::EffectCompensationHoldChirho {
                canonical_intent_line_chirho,
                verifier_chirho,
                authorization_chirho,
            },
        )
    }

    pub(crate) fn record_testkind_loss_witness_chirho(
        &mut self,
        request_chirho: AppendRequestChirho,
    ) -> Result<ResidentLedgerAppendReceiptChirho, ResidentLedgerAuthorityRefusalChirho> {
        let mutation_chirho =
            ResidentLedgerMutationChirho::TestkindLossWitnessTransferChirho { request_chirho };
        if mutation_chirho.allows_active_handoff_chirho() {
            return Err(
                ResidentLedgerAuthorityRefusalChirho::TestkindLossWitnessExemptLaneRefusedChirho,
            );
        }
        self.append_with_current_fence_chirho(mutation_chirho)
    }

    /// Advance this group's sink winner-term cell mid-life, under verified revoke evidence.
    ///
    /// This is the production entry for `sink_term_revoke_chirho`'s lawful advance — the operation
    /// that lifts the compensation fence after a term bump stranded it. It takes the two guards the
    /// advance requires from the resident's own fields rather than from a caller: the local
    /// leadership generation guard supplies the FRESHNESS coordinate (its published Raft term), and
    /// the writer lock guard supplies the exclusive storage namespace the cut is authenticated
    /// against. The AUTHORITY coordinate is read out of the signed observation inside the operation
    /// and is never a caller argument.
    ///
    /// The two guards map through DIFFERENT refusals on purpose: a generation refusal means this
    /// node is not the live writer, a writer-lock refusal means the fence namespace is not held.
    /// Collapsing them would report a leadership loss as a storage fault.
    pub(crate) fn accept_new_winner_term_chirho(
        &mut self,
        observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
        adopted_checkpoint_ref_chirho: &str,
        held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    ) -> Result<u64, ResidentLedgerAuthorityRefusalChirho> {
        let local_authority_chirho = self.local_authority_chirho.clone();
        let generation_guard_chirho = local_authority_chirho
            .try_acquire_chirho()
            .map_err(local_generation_refusal_chirho)?;
        let writer_lock_guard_chirho = self
            .writer_lock_chirho
            .try_acquire_chirho()
            .map_err(writer_fence_refusal_chirho)?;
        let advanced_chirho = revoke_and_accept_new_winner_term_chirho(
            &writer_lock_guard_chirho,
            &self.group_chirho,
            observation_chirho,
            adopted_checkpoint_ref_chirho,
            held_verifier_chirho,
            &generation_guard_chirho,
        )
        .map_err(|refusal_chirho| {
            ResidentLedgerAuthorityRefusalChirho::LawfulSinkTermAdvanceRefusedChirho {
                detail_chirho: refusal_chirho.to_string(),
            }
        })?;
        Ok(advanced_chirho.accepted_term_chirho())
    }

    /// AUTHORITY IMPLEMENTATION. This is where the release is actually decided: the checkpoint and
    /// active head are re-authenticated and the head ref is superseded.
    ///
    /// `ResidentEffectJournalHandleChirho::release_converged_gd7_hold_chirho` carries the SAME NAME
    /// one layer outward and is only the mailbox wire wrapper. The pair is a delegation pattern, not
    /// a wrong name — but a census of this name returns BOTH layers, so resolve which receiver a
    /// call site has before reading a count as evidence about either one.
    pub(crate) fn release_converged_gd7_hold_chirho(
        &mut self,
        adopted_checkpoint_ref_chirho: &str,
        convergence_chirho: &ConvergedReadReplicaChirho,
        held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    ) -> Result<(), ResidentLedgerAuthorityRefusalChirho> {
        let writer_lock_guard_chirho = self
            .writer_lock_chirho
            .try_acquire_chirho()
            .map_err(writer_fence_refusal_chirho)?;
        release_converged_reconciliation_hold_chirho(
            &writer_lock_guard_chirho,
            &self.group_chirho,
            adopted_checkpoint_ref_chirho,
            convergence_chirho,
            held_verifier_chirho,
        )
        .map_err(|refusal_chirho| {
            ResidentLedgerAuthorityRefusalChirho::WriterFenceRefusedChirho {
                detail_chirho: refusal_chirho.to_string(),
            }
        })
    }

    pub(crate) fn record_effect_terminal_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        intent_verifier_chirho: &dyn EffectIntentSignerPortChirho,
        canonical_terminal_line_chirho: &str,
        terminal_verifier_chirho: &dyn EffectTerminalSignerPortChirho,
    ) -> Result<ResidentLedgerAppendReceiptChirho, ResidentLedgerAuthorityRefusalChirho> {
        self.append_with_current_fence_chirho(ResidentLedgerMutationChirho::EffectTerminalChirho {
            canonical_intent_line_chirho,
            intent_verifier_chirho,
            canonical_terminal_line_chirho,
            terminal_verifier_chirho,
        })
    }

    pub(crate) fn effect_intent_cut_chirho(
        &self,
        handoff_read_chirho: Option<&LocalAppendHandoffReadGenerationChirho>,
    ) -> Result<EffectIntentJournalCutChirho, ResidentLedgerAuthorityRefusalChirho> {
        self.probe_for_read_chirho(handoff_read_chirho)?;
        Ok(self
            .journal_chirho
            .as_ref()
            .expect("resident authority retains its journal")
            .effect_intent_cut_chirho())
    }

    pub(crate) fn current_continuation_chirho(
        &self,
        kind_id_chirho: &AssetKindIdChirho,
        handoff_read_chirho: Option<&LocalAppendHandoffReadGenerationChirho>,
    ) -> Result<Option<EffectCommitContinuationViewChirho>, ResidentLedgerAuthorityRefusalChirho>
    {
        self.probe_for_read_chirho(handoff_read_chirho)?;
        Ok(self
            .journal_chirho
            .as_ref()
            .expect("resident authority retains its journal")
            .current_continuation_chirho(kind_id_chirho)
            .map(|continuation_chirho| EffectCommitContinuationViewChirho {
                kind_id_chirho: continuation_chirho.policy_chirho.kind_id_chirho,
                kind_policy_ref_chirho: continuation_chirho.kind_policy_ref_chirho,
                settlement_owner_present_chirho: continuation_chirho
                    .policy_chirho
                    .settlement_owner_chirho
                    .is_some(),
            }))
    }

    pub(crate) fn active_effect_intent_refs_chirho(
        &self,
        handoff_read_chirho: Option<&LocalAppendHandoffReadGenerationChirho>,
    ) -> Result<Vec<DigestChirho>, ResidentLedgerAuthorityRefusalChirho> {
        self.probe_for_read_chirho(handoff_read_chirho)?;
        Ok(self
            .journal_chirho
            .as_ref()
            .expect("resident authority retains its journal")
            .active_effect_intent_refs_chirho())
    }

    pub(crate) fn effect_intent_journal_state_chirho(
        &self,
        intent_ref_chirho: &DigestChirho,
        handoff_read_chirho: Option<&LocalAppendHandoffReadGenerationChirho>,
    ) -> Result<Option<EffectIntentJournalStateChirho>, ResidentLedgerAuthorityRefusalChirho> {
        self.probe_for_read_chirho(handoff_read_chirho)?;
        Ok(self
            .journal_chirho
            .as_ref()
            .expect("resident authority retains its journal")
            .effect_intent_journal_state_chirho(intent_ref_chirho))
    }

    pub(crate) fn verified_effect_receipt_inventory_chirho(
        &self,
        handoff_read_chirho: Option<&LocalAppendHandoffReadGenerationChirho>,
    ) -> Result<Vec<VerifiedEffectReceiptInventoryEntryChirho>, ResidentLedgerAuthorityRefusalChirho>
    {
        self.probe_for_read_chirho(handoff_read_chirho)?;
        Ok(self
            .journal_chirho
            .as_ref()
            .expect("resident authority retains its journal")
            .verified_effect_receipt_inventory_chirho())
    }

    /// Verify that everything appended AFTER a handoff's source cut is compensation-CLASS, and that
    /// the traversal REACHED the cut anchor.
    ///
    /// # WHAT THIS DOES NOT VERIFY — read this before trusting the name
    ///
    /// The name used to say "is lawful compensation". It was renamed because that asserted two
    /// properties this function does not establish, and a name is read at every call site by people
    /// who never open the file.
    ///
    /// - **WHICH RECONCILIATION a record belongs to: FORK-IMPOSSIBLE here, not merely unimplemented.**
    ///   GD7 compensates effects committed on the LOSING fork's journal. The winner's receipt window
    ///   ingests only its own journal's committed records and restores from its own checkpoint, so the
    ///   deposed fork's effect roots were never present winner-side. No accessor, no port, and no
    ///   widening of reach fixes absence — the data was never on this side. Measured 2026-08-07 by
    ///   three seats; the registered review invariant's "wrong-reconciliation" wording was amended
    ///   for exactly this reason.
    /// - **COORDINATE VALIDITY — that a record's key is a genuinely DERIVED compensation coordinate:
    ///   designed, accepted, and PRIVACY-GATED, not built.** So a FABRICATED compensation-lineage key
    ///   passes this walk today. The check would resolve the record's intent and require
    ///   `effect_compensation_key_chirho(original_effect_key) == idempotency_key`; it cannot be built
    ///   yet because the intent line carries `AttributionChirho::CauserChirho::principal_chirho`,
    ///   documented in its own type as unvalidated identifying free text, and no coordinate-only
    ///   projection exists on either the read or the write side. Two named cures: a coordinate-only
    ///   evidence surface (its own brick, QUEUED UNSCHEDULED), or an explicit privacy ruling on
    ///   reading within the trust domain. Neither is defaulted.
    ///
    /// Both are recorded as residuals beside the prerequisite's A9. This is ADDITIVE hardening the
    /// walk has never had, so their absence is the status quo rather than a regression.
    ///
    /// Half (b) of D1. Before the winner-side compensation lane existed, an active handoff froze
    /// every append, so "the live tail equals the cut" was an invariant. The lane is the one mutation
    /// that can move it, which would otherwise make the handoff un-restorable — so restoration now
    /// admits a forward extension, but only one it has READ and CLASSIFIED.
    ///
    /// THE BOUND CONTAINS NO NUMBER. It is not `seq_delta <= N` and takes no caller maximum; a bound
    /// a caller can widen is not a bound. The extension is bounded by what the classifier ADMITS,
    /// and both endpoints are actor-derived — the anchor from this actor's own verified handoff, the
    /// frozen tail from its own journal.
    ///
    /// FAIL-CLOSED ON TRAVERSAL, not just on content. Success requires REACHING THE ANCHOR after
    /// consuming every page. Cursor exhaustion, a page limit, or an unread remainder all refuse,
    /// because a prefix that classifies clean says nothing about records nobody read — and a clean
    /// prefix is indistinguishable from a clean whole unless termination is checked explicitly. The
    /// predicate is "reached the anchor AND every record compensation-class", never "no wrong-class
    /// record was seen", which is true of a traversal that read nothing.
    pub(crate) fn verify_post_cut_extension_class_and_anchor_chirho(
        &self,
        anchor_seq_chirho: u64,
        anchor_record_digest_chirho: &str,
    ) -> Result<(), ResidentLedgerAuthorityRefusalChirho> {
        let journal_chirho = self
            .journal_chirho
            .as_ref()
            .expect("resident authority retains its journal");
        let extension_refusal_chirho = |detail_chirho: String| {
            ResidentLedgerAuthorityRefusalChirho::Gd7PostCutExtensionRefusedChirho { detail_chirho }
        };
        let frozen_tail_chirho = journal_chirho.verified_losing_tail_chirho();
        let identity_chirho = LosingSuffixJournalIdentityChirho::new_chirho(
            journal_chirho.genesis_digest_chirho().clone(),
        );
        let anchor_chirho = LosingSuffixCoordinateChirho::new_chirho(
            anchor_seq_chirho,
            DigestChirho(anchor_record_digest_chirho.to_owned()),
        );

        let mut cursor_chirho = None;
        // Bounded per PAGE, unbounded in pages: the page size limits memory, never how much of the
        // extension must be read. Termination is by reaching the anchor, not by running out.
        for _page_chirho in 0..MAX_POST_CUT_EXTENSION_PAGES_CHIRHO {
            let mut request_chirho = LosingSuffixPageRequestChirho::new_chirho(
                identity_chirho.clone(),
                frozen_tail_chirho.coordinate_chirho().clone(),
                anchor_chirho.clone(),
                POST_CUT_EXTENSION_PAGE_RECORDS_CHIRHO,
                POST_CUT_EXTENSION_PAGE_BYTES_CHIRHO,
            );
            if let Some(cursor_chirho) = cursor_chirho.take() {
                request_chirho = request_chirho.with_cursor_chirho(cursor_chirho);
            }
            let page_chirho = journal_chirho
                .read_verified_losing_suffix_page_chirho(&request_chirho)
                .map_err(|error_chirho| extension_refusal_chirho(format!("{error_chirho:?}")))?;

            for record_chirho in page_chirho.records_newest_first_chirho() {
                // WRONG-CLASS refuses. The classifier is already fail-closed: a record that merely
                // LOOKS escrow-shaped stays ledger-only, so this cannot be satisfied by resemblance.
                match classify_effect_record_fact_chirho(record_chirho)
                    .map_err(|error_chirho| extension_refusal_chirho(format!("{error_chirho:?}")))?
                {
                    EffectRecordFactChirho::EffectHoldChirho {
                        lineage_chirho: EffectHoldLineageChirho::CompensationChirho,
                        ..
                    } => {}
                    other_chirho => {
                        return Err(extension_refusal_chirho(format!(
                            "post-cut record is not a compensation hold: {other_chirho:?}"
                        )));
                    }
                }
            }

            if page_chirho.reached_anchor_chirho() {
                return Ok(());
            }
            match page_chirho.next_cursor_chirho() {
                Some(next_chirho) => cursor_chirho = Some(next_chirho.clone()),
                // No cursor and no anchor means the traversal ENDED without covering the extension.
                None => {
                    return Err(extension_refusal_chirho(
                        "post-cut traversal ended before reaching the cut anchor".to_owned(),
                    ));
                }
            }
        }
        Err(extension_refusal_chirho(
            "post-cut traversal exceeded its page bound before reaching the cut anchor".to_owned(),
        ))
    }
}
