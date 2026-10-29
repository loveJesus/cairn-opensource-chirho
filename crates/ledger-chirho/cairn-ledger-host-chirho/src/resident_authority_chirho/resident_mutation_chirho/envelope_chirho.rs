// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Shared resident mutation envelope and its receipt-bound canary completion.

use super::*;
/// Which lane a resident mutation takes past the actor's early freeze diagnosis.
///
/// A named lane rather than a bool: at the call sites below, `OrdinaryChirho` reads as what it is,
/// and a future command cannot acquire the exemption by being passed a `true` nobody re-read.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ResidentMutationLaneChirho {
    /// Ordinary work — refused early, and again at the sink, while a handoff blocks mutations.
    OrdinaryChirho,
    /// The GD7 winner-side compensation append (ruled (a) by L.J. 2026-08-05). This lane only
    /// declines to refuse EARLY; it grants nothing. The seam re-derives the exemption from the
    /// node's own durable signed handoff head and the elector's exact in-memory marker, so a wrong
    /// lane here cannot admit an append the sink would refuse.
    Gd7CompensationChirho,
}

pub(super) fn execute_resident_mutation_chirho(
    mut envelope_chirho: ResidentMutationEnvelopeChirho<'_, '_, '_>,
    lane_chirho: ResidentMutationLaneChirho,
    command_kind_chirho: ResidentMutationCommandKindChirho,
    append_chirho: impl FnOnce(
        &mut ResidentLedgerAuthorityChirho<'_>,
    ) -> std::result::Result<
        ResidentLedgerAppendReceiptChirho,
        ResidentLedgerAuthorityRefusalChirho,
    >,
) -> ResidentEffectJournalResultChirho<EffectCommitJournalReceiptChirho> {
    let prepared_chirho = prepare_resident_mutation_chirho(&mut envelope_chirho, lane_chirho)?;
    let append_receipt_chirho =
        append_chirho(envelope_chirho.resident_chirho).map_err(resident_refusal_chirho)?;
    complete_resident_mutation_chirho(
        envelope_chirho,
        command_kind_chirho,
        prepared_chirho,
        append_receipt_chirho,
    )
}

pub(super) struct ResidentMutationEnvelopeChirho<
    'context_chirho,
    'resident_ports_chirho,
    'winner_ports_chirho,
> {
    pub(super) resident_chirho:
        &'context_chirho mut ResidentLedgerAuthorityChirho<'resident_ports_chirho>,
    pub(super) elector_chirho: &'context_chirho RaftWriterElectorChirho,
    pub(super) gd7_winner_store_chirho:
        &'context_chirho Gd7WinnerWitnessStoreChirho<'winner_ports_chirho>,
    pub(super) canary_store_chirho: &'context_chirho ShadowCanaryGenerationStoreChirho,
    pub(super) group_chirho: &'context_chirho ConsistencyGroupIdChirho,
    pub(super) node_chirho: &'context_chirho NodeIdChirho,
    pub(super) canary_state_chirho: &'context_chirho mut ResidentCanaryStateChirho,
    pub(super) append_barrier_state_chirho: &'context_chirho ResidentAppendBarrierRuntimeChirho,
}

pub(super) struct ResidentMutationPreparedChirho {
    local_authority_chirho: LocalAppendAuthorityHandleChirho,
    before_chirho: ResidentLedgerAuthorityReadinessChirho,
}

pub(super) fn prepare_resident_mutation_chirho(
    envelope_chirho: &mut ResidentMutationEnvelopeChirho<'_, '_, '_>,
    lane_chirho: ResidentMutationLaneChirho,
) -> ResidentEffectJournalResultChirho<ResidentMutationPreparedChirho> {
    // This early check exposes the freeze reason before canary work. The resident authority's
    // private append seam independently reacquires the same marker-bearing authority at the sink.
    //
    // ONE lane declines to refuse here (GD7 resume step, ruled (a)): the winner-side compensation
    // append, and only once the handoff is ACCEPTED with its durability confirmed —
    // `accepted_attempt_digest_chirho` yields nothing while unconfirmed or `Preparing`. This
    // precheck still grants nothing; it only stops pre-empting the seam's own decision.
    let compensation_lane_admitted_chirho = lane_chirho
        == ResidentMutationLaneChirho::Gd7CompensationChirho
        && envelope_chirho
            .append_barrier_state_chirho
            .accepted_gd7_attempt_digest_chirho()
            .is_some();
    if let Some(detail_chirho) = envelope_chirho
        .append_barrier_state_chirho
        .mutation_refusal_detail_chirho()
    {
        if !compensation_lane_admitted_chirho {
            return Err(unavailable_chirho(detail_chirho));
        }
    }
    ensure_canary_ready_chirho(
        envelope_chirho.canary_store_chirho,
        envelope_chirho.canary_state_chirho,
        envelope_chirho.group_chirho,
    )?;
    // Handoff-aware probes: under an active marker an ordinary probe acquisition refuses, so the
    // exempt lane must read its before/after readiness through the same exact-attempt read witness
    // the actor's other frozen-state reads use. Unfrozen callers take the ordinary probe unchanged.
    let local_authority_chirho = envelope_chirho
        .elector_chirho
        .local_append_authority_handle_chirho();
    let before_chirho = envelope_chirho
        .append_barrier_state_chirho
        .probe_resident_chirho(envelope_chirho.resident_chirho, &local_authority_chirho)
        .map_err(resident_refusal_chirho)?;
    verify_readiness_canary_alignment_chirho(
        &before_chirho,
        &envelope_chirho.canary_state_chirho.latest_ledger_cut_chirho,
        envelope_chirho.group_chirho,
    )
    // Named rather than generic since 2026-08-17: this is inside the exact function the Clause 14
    // loss witness calls first, and an unattributable refusal here is what left node loss and region
    // loss undiagnosable across three hosted windows. Window 4 then showed BOTH drills refusing here,
    // so the identity now carries WHICH coordinate moved -- tail advanced, or domain changed.
    .map_err(|error_chirho| {
        let identity_chirho = match classify_readiness_canary_alignment_chirho(
            &before_chirho,
            &envelope_chirho.canary_state_chirho.latest_ledger_cut_chirho,
            envelope_chirho.group_chirho,
        ) {
            Ok(Some(ResidentCanaryAlignmentMismatchChirho::TailSeqChirho)) => {
                EffectCommitJournalResidentRefusalIdentityChirho::CanaryTailSeqChirho
            }
            Ok(Some(ResidentCanaryAlignmentMismatchChirho::TailDigestChirho)) => {
                EffectCommitJournalResidentRefusalIdentityChirho::CanaryTailDigestChirho
            }
            Ok(Some(ResidentCanaryAlignmentMismatchChirho::ConsistencyGroupChirho)) => {
                EffectCommitJournalResidentRefusalIdentityChirho::CanaryConsistencyGroupChirho
            }
            // No mismatch on re-classification, or the group digest itself failed to compute: keep
            // the unnarrowed identity rather than inventing a coordinate we did not observe.
            Ok(None) | Err(_) => {
                EffectCommitJournalResidentRefusalIdentityChirho::ReadinessCanaryAlignmentChirho
            }
        };
        resident_refused_chirho(identity_chirho, &error_chirho.to_string())
    })?;
    Ok(ResidentMutationPreparedChirho {
        local_authority_chirho,
        before_chirho,
    })
}

pub(super) fn complete_resident_mutation_chirho(
    envelope_chirho: ResidentMutationEnvelopeChirho<'_, '_, '_>,
    command_kind_chirho: ResidentMutationCommandKindChirho,
    prepared_chirho: ResidentMutationPreparedChirho,
    append_receipt_chirho: ResidentLedgerAppendReceiptChirho,
) -> ResidentEffectJournalResultChirho<EffectCommitJournalReceiptChirho> {
    let ResidentMutationPreparedChirho {
        local_authority_chirho,
        before_chirho,
    } = prepared_chirho;
    let receipt_chirho = effect_receipt_chirho(&append_receipt_chirho);
    if let Err(error_chirho) = ensure_append_winner_term_index_chirho(
        envelope_chirho.gd7_winner_store_chirho,
        envelope_chirho.group_chirho,
        envelope_chirho.node_chirho,
        &before_chirho,
        &append_receipt_chirho,
    ) {
        return sticky_committed_refusal_chirho(
            envelope_chirho.canary_state_chirho,
            receipt_chirho,
            EffectCommitJournalCommittedEvidenceIdentityChirho::WinnerTermIndexEvidencePendingChirho,
            format!("GD7 winner term-first index is pending after commit: {error_chirho}"),
        );
    }
    let after_chirho = match probe_after_committed_append_chirho(
        envelope_chirho.resident_chirho,
        envelope_chirho.append_barrier_state_chirho,
        &local_authority_chirho,
        &append_receipt_chirho,
        command_kind_chirho,
    ) {
        Ok(after_chirho) => after_chirho,
        Err(PostAppendReprobeRefusalChirho::AuthorityChangedChirho) => {
            return sticky_committed_refusal_chirho(
                envelope_chirho.canary_state_chirho,
                receipt_chirho,
                EffectCommitJournalCommittedEvidenceIdentityChirho::JournalPostAppendAuthorityChangedEvidencePendingChirho,
                "resident post-append authority changed before durable reprobe",
            );
        }
        Err(PostAppendReprobeRefusalChirho::AuthorityChirho(error_chirho)) => {
            return sticky_committed_refusal_chirho(
                envelope_chirho.canary_state_chirho,
                receipt_chirho,
                EffectCommitJournalCommittedEvidenceIdentityChirho::JournalPostAppendReprobeEvidencePendingChirho,
                format!("resident journal reprobe failed after commit: {error_chirho}"),
            );
        }
    };

    if after_chirho.journal_tail_seq_chirho == before_chirho.journal_tail_seq_chirho {
        if append_receipt_chirho.append_chirho.seq_chirho > before_chirho.journal_tail_seq_chirho {
            return sticky_committed_refusal_chirho(
                envelope_chirho.canary_state_chirho,
                receipt_chirho,
                EffectCommitJournalCommittedEvidenceIdentityChirho::JournalReplayBeyondTailEvidencePendingChirho,
                "journal replay returned a receipt beyond an unchanged tail",
            );
        }
        return Ok(receipt_chirho);
    }
    let Some(expected_next_seq_chirho) = before_chirho.journal_tail_seq_chirho.checked_add(1)
    else {
        return sticky_committed_refusal_chirho(
            envelope_chirho.canary_state_chirho,
            receipt_chirho,
            EffectCommitJournalCommittedEvidenceIdentityChirho::JournalSequenceExhaustedEvidencePendingChirho,
            "resident journal sequence exhausted after a committed tail transition",
        );
    };
    if after_chirho.journal_tail_seq_chirho != expected_next_seq_chirho
        || append_receipt_chirho.append_chirho.seq_chirho != after_chirho.journal_tail_seq_chirho
        || append_receipt_chirho.append_chirho.record_digest_chirho
            != after_chirho.journal_tail_digest_chirho
    {
        return sticky_committed_refusal_chirho(
            envelope_chirho.canary_state_chirho,
            receipt_chirho,
            EffectCommitJournalCommittedEvidenceIdentityChirho::JournalDenseTailTransitionEvidencePendingChirho,
            "resident append did not produce one exact dense tail transition",
        );
    }

    let canary_append_cut_chirho = match canary_append_cut_chirho(&append_receipt_chirho) {
        Ok(canary_append_cut_chirho) => canary_append_cut_chirho,
        Err(error_chirho) => {
            return sticky_committed_refusal_chirho(
                envelope_chirho.canary_state_chirho,
                receipt_chirho,
                EffectCommitJournalCommittedEvidenceIdentityChirho::CanaryCutConstructionEvidencePendingChirho,
                format!("receipt-bound canary cut construction failed: {error_chirho}"),
            );
        }
    };
    let observation_chirho = observe_shadow_canary_chirho(
        envelope_chirho.elector_chirho,
        envelope_chirho.group_chirho,
        envelope_chirho.node_chirho,
        canary_append_cut_chirho,
        append_receipt_chirho
            .append_chirho
            .hlc_chirho
            .physical_ms_chirho,
    );
    let pending_chirho = PendingCanaryObservationChirho {
        receipt_chirho: receipt_chirho.clone(),
        origin_identity_chirho:
            EffectCommitJournalCommittedEvidenceIdentityChirho::CanaryPersistenceEvidencePendingChirho,
        observation_chirho,
    };
    match envelope_chirho
        .canary_store_chirho
        .append_observation_chirho(pending_chirho.observation_chirho.clone())
    {
        Ok(_evidence_chirho) => {
            envelope_chirho.canary_state_chirho.latest_ledger_cut_chirho =
                match ShadowCanaryLedgerCutChirho::from_append_cut_chirho(
                    &pending_chirho.observation_chirho.append_cut_chirho,
                    envelope_chirho.group_chirho,
                ) {
                    Ok(cut_chirho) => cut_chirho,
                    Err(error_chirho) => {
                        return sticky_committed_refusal_chirho(
                            envelope_chirho.canary_state_chirho,
                            receipt_chirho,
                            EffectCommitJournalCommittedEvidenceIdentityChirho::CanaryCutDomainEvidencePendingChirho,
                            format!("committed canary cut domain refused: {error_chirho}"),
                        );
                    }
                };
            if !pending_chirho
                .observation_chirho
                .cutover_would_permit_chirho
            {
                return sticky_committed_refusal_chirho(
                    envelope_chirho.canary_state_chirho,
                    receipt_chirho,
                    EffectCommitJournalCommittedEvidenceIdentityChirho::CanaryLeaseAuthorityEvidencePendingChirho,
                    "canary recorded that the committed append lacked elected lease authority",
                );
            }
            Ok(receipt_chirho)
        }
        Err(error_chirho) => {
            let origin_identity_chirho = pending_chirho.origin_identity_chirho;
            envelope_chirho.canary_state_chirho.pending_chirho = Some(pending_chirho);
            Err(committed_pending_chirho(
                &receipt_chirho,
                origin_identity_chirho,
                format!("receipt-bound canary append failed: {error_chirho}"),
            ))
        }
    }
}

pub(super) fn ensure_canary_ready_chirho(
    canary_store_chirho: &ShadowCanaryGenerationStoreChirho,
    canary_state_chirho: &mut ResidentCanaryStateChirho,
    group_chirho: &ConsistencyGroupIdChirho,
) -> ResidentEffectJournalResultChirho<()> {
    if let Some(sticky_refusal_chirho) = &canary_state_chirho.sticky_refusal_chirho {
        return Err(committed_pending_chirho(
            &sticky_refusal_chirho.receipt_chirho,
            sticky_refusal_chirho.origin_identity_chirho,
            sticky_refusal_chirho.detail_chirho.clone(),
        ));
    }
    let Some(pending_chirho) = canary_state_chirho.pending_chirho.take() else {
        return Ok(());
    };
    match canary_store_chirho.append_observation_chirho(pending_chirho.observation_chirho.clone()) {
        Ok(_evidence_chirho) => {
            canary_state_chirho.latest_ledger_cut_chirho =
                match ShadowCanaryLedgerCutChirho::from_append_cut_chirho(
                    &pending_chirho.observation_chirho.append_cut_chirho,
                    group_chirho,
                ) {
                    Ok(cut_chirho) => cut_chirho,
                    Err(error_chirho) => {
                        return sticky_committed_refusal_chirho(
                            canary_state_chirho,
                            pending_chirho.receipt_chirho,
                            pending_chirho.origin_identity_chirho,
                            format!("committed canary cut domain refused: {error_chirho}"),
                        );
                    }
                };
            if !pending_chirho
                .observation_chirho
                .cutover_would_permit_chirho
            {
                return sticky_committed_refusal_chirho(
                    canary_state_chirho,
                    pending_chirho.receipt_chirho,
                    pending_chirho.origin_identity_chirho,
                    "canary recorded that the committed append lacked elected lease authority",
                );
            }
            Ok(())
        }
        Err(error_chirho) => {
            let refusal_chirho = committed_pending_chirho(
                &pending_chirho.receipt_chirho,
                pending_chirho.origin_identity_chirho,
                format!("receipt-bound canary retry failed: {error_chirho}"),
            );
            canary_state_chirho.pending_chirho = Some(pending_chirho);
            Err(refusal_chirho)
        }
    }
}

pub(super) fn sticky_committed_refusal_chirho<OutputChirho>(
    canary_state_chirho: &mut ResidentCanaryStateChirho,
    receipt_chirho: EffectCommitJournalReceiptChirho,
    origin_identity_chirho: EffectCommitJournalCommittedEvidenceIdentityChirho,
    detail_chirho: impl Into<String>,
) -> ResidentEffectJournalResultChirho<OutputChirho> {
    let detail_chirho = detail_chirho.into();
    canary_state_chirho.sticky_refusal_chirho = Some(StickyCommittedRefusalChirho {
        receipt_chirho: receipt_chirho.clone(),
        origin_identity_chirho,
        detail_chirho: detail_chirho.clone(),
    });
    Err(committed_pending_chirho(
        &receipt_chirho,
        origin_identity_chirho,
        detail_chirho,
    ))
}

pub(super) fn verify_canary_generation_posture_chirho(
    current_chirho: &VerifiedShadowCanaryCurrentGenerationChirho,
    group_chirho: &ConsistencyGroupIdChirho,
) -> Result<()> {
    let window_chirho = current_chirho.window_chirho();
    if current_chirho.generation_chirho() == 0 && window_chirho.is_none() {
        bail!("resident canary generation zero is empty");
    }
    if let Some(window_chirho) = window_chirho {
        if &window_chirho.group_chirho != group_chirho {
            bail!("resident canary consistency group differs from the selected root");
        }
        if window_chirho.window_len_chirho == 0
            || window_chirho.permit_count_chirho != window_chirho.window_len_chirho
            || window_chirho.refusal_count_chirho != 0
        {
            bail!("resident canary window contains an authority refusal");
        }
    }
    Ok(())
}

pub(super) fn verify_preflight_canary_alignment_chirho(
    journal_chirho: &LedgerJournalChirho<'_>,
    ledger_cut_chirho: &ShadowCanaryLedgerCutChirho,
    group_chirho: &ConsistencyGroupIdChirho,
) -> Result<()> {
    if journal_chirho.tail_seq_chirho() != ledger_cut_chirho.append_seq_chirho()
        || journal_chirho.tail_line_digest_chirho().0
            != ledger_cut_chirho.append_record_digest_chirho()
        || journal_chirho.tail_hlc_chirho().physical_ms_chirho
            != ledger_cut_chirho.append_hlc_physical_ms_chirho()
        || journal_chirho.tail_hlc_chirho().logical_chirho
            != ledger_cut_chirho.append_hlc_logical_chirho()
        || journal_chirho.current_epoch_chirho() != ledger_cut_chirho.record_epoch_chirho()
        || consistency_group_digest_chirho(group_chirho)?
            != ledger_cut_chirho
                .consistency_group_digest_chirho()
                .as_str_chirho()
    {
        bail!("resident journal tail is not bound to the latest canary evidence");
    }
    Ok(())
}

/// WHICH coordinate of the canary alignment mismatched, as a closed set.
///
/// The four coordinates used to fail behind one message, so a Clause 14 loss drill could observe
/// only "misaligned" and never which of seq, digest, epoch or group moved. Measured across four
/// hosted windows, node loss and region loss both refuse here, so narrowing this is what tells the
/// drill whether the tail ADVANCED (seq/digest) or the domain CHANGED (epoch/group).
///
/// Deliberately carries no values — the Stops bar journal cuts and authority coordinates from any
/// report, so the field NAME travels and the coordinate itself never does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub(super) enum ResidentCanaryAlignmentMismatchChirho {
    TailSeqChirho,
    TailDigestChirho,
    ConsistencyGroupChirho,
}

impl ResidentCanaryAlignmentMismatchChirho {
    pub(super) const fn as_str_chirho(self) -> &'static str {
        match self {
            Self::TailSeqChirho => "tail-seq",
            Self::TailDigestChirho => "tail-digest",
            Self::ConsistencyGroupChirho => "consistency-group",
        }
    }
}

pub(super) fn classify_readiness_canary_alignment_chirho(
    readiness_chirho: &ResidentLedgerAuthorityReadinessChirho,
    ledger_cut_chirho: &ShadowCanaryLedgerCutChirho,
    group_chirho: &ConsistencyGroupIdChirho,
) -> Result<Option<ResidentCanaryAlignmentMismatchChirho>> {
    // Ordered most-specific-first so the reported coordinate is stable when several differ at once.
    //
    // THE JOURNAL-EPOCH COORDINATE WAS REMOVED 2026-08-17, and its absence is the fix rather than a
    // gap. It compared the journal's GRANT (`current_epoch_chirho`) against the cut's FENCE epoch at
    // commit, so the only state it could catch was "the grant moved without a commit" — a state the
    // journal EXPLICITLY SUPPORTS: `advance_epoch_chirho`'s own doc says a never-used advance does
    // not survive a restart, and the journal separates grant from record precisely to hold it.
    //
    // Because `append_with_current_fence_chirho` advances the epoch BEFORE validating the mutation,
    // one refused append — an ordinary admission rejection is enough — left the grant ahead of the
    // cut with no way back short of a process restart, wedging every later mutation. Removing the
    // coordinate loses no fault detection: a genuinely diverged record still refuses on tail seq or
    // tail digest, which move with the record in the same block.
    if consistency_group_digest_chirho(group_chirho)?
        != ledger_cut_chirho
            .consistency_group_digest_chirho()
            .as_str_chirho()
    {
        return Ok(Some(
            ResidentCanaryAlignmentMismatchChirho::ConsistencyGroupChirho,
        ));
    }
    if readiness_chirho.journal_tail_seq_chirho != ledger_cut_chirho.append_seq_chirho() {
        return Ok(Some(ResidentCanaryAlignmentMismatchChirho::TailSeqChirho));
    }
    if readiness_chirho.journal_tail_digest_chirho.0
        != ledger_cut_chirho.append_record_digest_chirho()
    {
        return Ok(Some(
            ResidentCanaryAlignmentMismatchChirho::TailDigestChirho,
        ));
    }
    Ok(None)
}

pub(super) fn verify_readiness_canary_alignment_chirho(
    readiness_chirho: &ResidentLedgerAuthorityReadinessChirho,
    ledger_cut_chirho: &ShadowCanaryLedgerCutChirho,
    group_chirho: &ConsistencyGroupIdChirho,
) -> Result<()> {
    if let Some(mismatch_chirho) = classify_readiness_canary_alignment_chirho(
        readiness_chirho,
        ledger_cut_chirho,
        group_chirho,
    )? {
        bail!(
            "resident authority tail is ahead of or differs from its canary evidence ({})",
            mismatch_chirho.as_str_chirho()
        );
    }
    Ok(())
}

fn canary_append_cut_chirho(
    receipt_chirho: &ResidentLedgerAppendReceiptChirho,
) -> ResidentEffectJournalResultChirho<ShadowCanaryAppendCutChirho> {
    let fence_group_digest_chirho =
        consistency_group_digest_chirho(&receipt_chirho.fence_chirho.group_chirho)
            .map_err(|error_chirho| refused_chirho(&error_chirho.to_string()))?;
    Ok(ShadowCanaryAppendCutChirho {
        append_seq_chirho: receipt_chirho.append_chirho.seq_chirho,
        append_record_digest_chirho: receipt_chirho.append_chirho.record_digest_chirho.0.clone(),
        append_hlc_physical_ms_chirho: receipt_chirho.append_chirho.hlc_chirho.physical_ms_chirho,
        append_hlc_logical_chirho: receipt_chirho.append_chirho.hlc_chirho.logical_chirho,
        process_generation_chirho: receipt_chirho.process_generation_chirho,
        durable_term_chirho: receipt_chirho.published_raft_term_chirho,
        fence_epoch_chirho: receipt_chirho.fence_chirho.epoch_chirho,
        fence_group_digest_chirho,
    })
}
