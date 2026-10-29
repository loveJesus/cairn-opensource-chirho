// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The saga driver: two-phase escrow over real journals — holds acquired in ASCENDING canonical
//! order (the two-phase lock law), then finalize-all or release-all — resumable from ANY crash cut
//! because every journal effect is re-learnable from the journals' own admission laws (the
//! exact-triple/five-way escrow design consumed as idempotency), and the intent is durable before
//! the first journal append.
//!
//! THE COMPOSITION INVARIANT (second-seat #5028 — the escrow-op analog of the single-writer law):
//! exactly ONE coordinator (or state-sharing instances that re-derive from the shared saga log
//! FIRST) per saga-id namespace, and NO other journal client ever authors escrow ops carrying
//! coordinator-owned (account, saga, step) triples. The journal's 9b verifies WHICH hold (the
//! exact five-way match), not WHO may consume it — R4's control identity is an identification
//! badge, not a caller binding — so this exclusivity is compositional, not journal-enforced.
//! Every resume disambiguation below (hold-absent ⇒ already-done-for-this-saga) is sound ONLY
//! within it; if it ever breaks (a foreign RELEASE consuming a hold), conservation still holds
//! but a "settled" claim could be false. ENFR candidate: enforce caller binding at admission in
//! the A6/multi-coordinator era.

use crate::log_chirho::{
    append_saga_op_chirho, load_saga_log_chirho, receipt_evidence_chirho, SagaPhaseChirho,
    SagaStateChirho,
};
use crate::record_chirho::{
    derive_saga_id_chirho, SagaAbortReasonChirho, SagaDecisionChirho, SagaOpChirho,
    SagaOutcomeChirho, SagaStepEvidenceChirho, SagaStepPlanChirho,
};
use anyhow::{anyhow, bail, Result};
use cairn_ledger_log_chirho::admission_chirho::{
    AdmissionRejectChirho, CurrentContinuationPolicyChirho, EscrowHoldKeyChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{
    AppendLegRequestChirho, AppendReceiptChirho, AppendRequestChirho, JournalErrorChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerClockPortChirho, LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, ClusterIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::EscrowControlChirho;
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerOpChirho, LegDeltaChirho};
use cairn_ledger_model_chirho::LogIdChirho;

/// The coordinator's ONLY power over money: appending admission-gated requests to a named journal.
/// Implementations route to real engines; the journals' fences stay the only money gates (#4901 a).
pub trait SagaJournalRouterChirho {
    fn append_chirho(
        &mut self,
        cluster_chirho: &ClusterIdChirho,
        request_chirho: AppendRequestChirho,
    ) -> Result<AppendReceiptChirho, JournalErrorChirho>;

    /// Read-only: the journal's unconsumed held amount for an exact-triple key, if any. EVIDENCE
    /// for retry disambiguation (a consumed hold can mask as a builder-fold Arithmetic reject) —
    /// never a money gate.
    fn active_hold_chirho(
        &self,
        cluster_chirho: &ClusterIdChirho,
        key_chirho: &EscrowHoldKeyChirho,
    ) -> Option<u64>;

    /// Read-only: the CURRENT continuation policy for a stable kind on this cluster's journal —
    /// the SAME resolve the CF3 terminal door uses (#5127/#5151). The coordinator settles an
    /// R1-era hold under the CURRENT ref so a mid-saga amend can never strand it; no caller ref
    /// exists (the stable kind comes from the coordinator's OWN durable plan).
    fn current_continuation_chirho(
        &self,
        cluster_chirho: &ClusterIdChirho,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> Option<CurrentContinuationPolicyChirho>;
}

/// The coordinator's injected ports: its OWN log storage + OWN root (never a journal key, #4901 b)
/// + the shared clock.
pub struct SagaCoordinatorChirho<'ports_chirho> {
    pub storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    pub root_chirho: &'ports_chirho dyn LedgerSignerPortChirho,
    pub clock_chirho: &'ports_chirho dyn LedgerClockPortChirho,
    pub path_chirho: StoragePathChirho,
    pub saga_log_id_chirho: String,
}

/// What a completed drive reports (the saga's durable outcome, never in-memory-only state).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SagaRunReportChirho {
    pub saga_id_chirho: DigestChirho,
    pub outcome_chirho: SagaOutcomeChirho,
}

impl SagaCoordinatorChirho<'_> {
    /// Open and drive one saga to a durable close. Steps are sorted into the ASCENDING canonical
    /// hold order BY LOG-ID DIGEST (the frozen §12 law, model-checked in model_cf2_lockorder):
    /// every concurrent saga acquires in the same global order, so circular wait is impossible.
    /// Re-running a token that already has an intent RESUMES it instead (idempotent entry).
    pub fn run_saga_chirho(
        &self,
        journals_chirho: &mut dyn SagaJournalRouterChirho,
        token_chirho: &str,
        mut steps_chirho: Vec<SagaStepPlanChirho>,
        ttl_ms_chirho: u64,
    ) -> Result<SagaRunReportChirho> {
        if steps_chirho.is_empty() {
            bail!("a saga needs at least one step");
        }
        steps_chirho.sort_by_key(step_lock_digest_chirho);
        let saga_id_chirho = derive_saga_id_chirho(&self.saga_log_id_chirho, token_chirho);
        let loaded_chirho = load_saga_log_chirho(
            self.storage_chirho,
            self.root_chirho,
            &self.path_chirho,
            &self.saga_log_id_chirho,
        )?;
        if let Some(state_chirho) = loaded_chirho.sagas_chirho.get(&saga_id_chirho) {
            // The token already ran (possibly to a crash cut): resume, never re-plan.
            return self.resume_one_chirho(journals_chirho, &saga_id_chirho, state_chirho.clone());
        }
        self.append_chirho(
            &saga_id_chirho,
            SagaOpChirho::IntentChirho {
                token_chirho: token_chirho.to_owned(),
                steps_chirho: steps_chirho.clone(),
                opened_at_ms_chirho: self.clock_chirho.physical_now_ms_chirho(),
                ttl_ms_chirho,
            },
        )?;
        let state_chirho = self.load_state_chirho(&saga_id_chirho)?;
        self.resume_one_chirho(journals_chirho, &saga_id_chirho, state_chirho)
    }

    /// Resume EVERY open saga in the log to a durable close (the crash-recovery entry).
    pub fn resume_all_chirho(
        &self,
        journals_chirho: &mut dyn SagaJournalRouterChirho,
    ) -> Result<Vec<SagaRunReportChirho>> {
        let loaded_chirho = load_saga_log_chirho(
            self.storage_chirho,
            self.root_chirho,
            &self.path_chirho,
            &self.saga_log_id_chirho,
        )?;
        let mut reports_chirho = Vec::new();
        for (saga_id_chirho, state_chirho) in loaded_chirho.sagas_chirho {
            if let SagaPhaseChirho::ClosedChirho { .. } = state_chirho.phase_chirho {
                continue;
            }
            reports_chirho.push(self.resume_one_chirho(
                journals_chirho,
                &saga_id_chirho,
                state_chirho,
            )?);
        }
        Ok(reports_chirho)
    }

    /// Drive ONE saga from wherever its durable state stands to a durable close.
    fn resume_one_chirho(
        &self,
        journals_chirho: &mut dyn SagaJournalRouterChirho,
        saga_id_chirho: &DigestChirho,
        mut state_chirho: SagaStateChirho,
    ) -> Result<SagaRunReportChirho> {
        loop {
            match state_chirho.phase_chirho.clone() {
                SagaPhaseChirho::HoldingChirho => {
                    self.drive_hold_phase_chirho(journals_chirho, saga_id_chirho, &state_chirho)?;
                }
                SagaPhaseChirho::DecidedChirho { decision_chirho } => {
                    match decision_chirho {
                        SagaDecisionChirho::FinalizeChirho => self.drive_settle_phase_chirho(
                            journals_chirho,
                            saga_id_chirho,
                            &state_chirho,
                        )?,
                        SagaDecisionChirho::AbortChirho { .. } => self.drive_release_phase_chirho(
                            journals_chirho,
                            saga_id_chirho,
                            &state_chirho,
                        )?,
                    };
                }
                SagaPhaseChirho::ClosedChirho { outcome_chirho } => {
                    return Ok(SagaRunReportChirho {
                        saga_id_chirho: saga_id_chirho.clone(),
                        outcome_chirho,
                    });
                }
            }
            state_chirho = self.load_state_chirho(saga_id_chirho)?;
        }
    }

    /// Phase 1: acquire every un-held step IN PLAN ORDER (already canonical-ascending), then
    /// decide. Any real refusal aborts; the TTL expiring before the decision aborts.
    fn drive_hold_phase_chirho(
        &self,
        journals_chirho: &mut dyn SagaJournalRouterChirho,
        saga_id_chirho: &DigestChirho,
        state_chirho: &SagaStateChirho,
    ) -> Result<()> {
        for (index_chirho, plan_chirho) in state_chirho.steps_chirho.iter().enumerate() {
            let step_chirho = (index_chirho + 1) as u32;
            if state_chirho.held_chirho.contains(&step_chirho) {
                continue;
            }
            let outcome_chirho = journals_chirho.append_chirho(
                &plan_chirho.cluster_chirho,
                self.hold_request_chirho(saga_id_chirho, step_chirho, plan_chirho),
            );
            match outcome_chirho {
                Ok(receipt_chirho) => {
                    self.append_chirho(
                        saga_id_chirho,
                        SagaOpChirho::StepHeldChirho {
                            step_chirho,
                            evidence_chirho: receipt_evidence_chirho(&receipt_chirho),
                        },
                    )?;
                }
                Err(JournalErrorChirho::AdmissionChirho {
                    reject_chirho:
                        AdmissionRejectChirho::DuplicateEscrowHoldChirho
                        | AdmissionRejectChirho::IdempotencyDuplicateChirho,
                }) => {
                    // The hold landed before a crash cut — re-learned from the journal's own law.
                    self.append_chirho(
                        saga_id_chirho,
                        SagaOpChirho::StepHeldChirho {
                            step_chirho,
                            evidence_chirho: SagaStepEvidenceChirho::ResumedObservationChirho,
                        },
                    )?;
                }
                Err(refusal_chirho) => {
                    // A REAL refusal (funds, membership, policy…): decide abort — phase 2 releases.
                    self.append_chirho(
                        saga_id_chirho,
                        SagaOpChirho::DecisionChirho {
                            decision_chirho: SagaDecisionChirho::AbortChirho {
                                reason_chirho: SagaAbortReasonChirho::HoldRefusedChirho {
                                    detail_chirho: format!("{refusal_chirho:?}"),
                                },
                            },
                        },
                    )?;
                    return Ok(());
                }
            }
        }
        // Every step held. The durable TTL law: expiry before the decision aborts.
        let decision_chirho =
            if self.clock_chirho.physical_now_ms_chirho() > state_chirho.deadline_ms_chirho() {
                SagaDecisionChirho::AbortChirho {
                    reason_chirho: SagaAbortReasonChirho::TtlExpiredChirho,
                }
            } else {
                SagaDecisionChirho::FinalizeChirho
            };
        self.append_chirho(
            saga_id_chirho,
            SagaOpChirho::DecisionChirho { decision_chirho },
        )?;
        Ok(())
    }

    /// Phase 2 (finalize): settle every held-but-unconsumed step. UnknownEscrowHold or an
    /// idempotency duplicate after a finalize decision can only mean "already settled" (the
    /// decision required all-held; this coordinator never releases after a finalize decision).
    fn drive_settle_phase_chirho(
        &self,
        journals_chirho: &mut dyn SagaJournalRouterChirho,
        saga_id_chirho: &DigestChirho,
        state_chirho: &SagaStateChirho,
    ) -> Result<()> {
        for (index_chirho, plan_chirho) in state_chirho.steps_chirho.iter().enumerate() {
            let step_chirho = (index_chirho + 1) as u32;
            if state_chirho.consumed_chirho.contains(&step_chirho) {
                continue;
            }
            // Settle under the CURRENT continuation ref (#5127/#5151): a mid-saga amend that
            // superseded the plan's ref must never strand the hold. None/unresolvable refuses
            // with the hold LIVE — never strand-by-forcing a bad settle.
            let continuation_chirho =
                self.current_continuation_chirho(journals_chirho, plan_chirho)?;
            let request_chirho = self.finalize_request_chirho(
                saga_id_chirho,
                step_chirho,
                plan_chirho,
                &continuation_chirho,
            )?;
            let outcome_chirho =
                journals_chirho.append_chirho(&plan_chirho.cluster_chirho, request_chirho);
            let evidence_chirho = match outcome_chirho {
                Ok(receipt_chirho) => receipt_evidence_chirho(&receipt_chirho),
                Err(JournalErrorChirho::AdmissionChirho {
                    reject_chirho:
                        AdmissionRejectChirho::UnknownEscrowHoldChirho
                        | AdmissionRejectChirho::IdempotencyDuplicateChirho,
                }) => SagaStepEvidenceChirho::ResumedObservationChirho,
                Err(error_chirho) => {
                    // The builder-fold can mask an already-consumed hold as Arithmetic (the decoy
                    // lesson): consult the journal's own index — absent hold after an all-held
                    // decision can only mean CONSUMED (this coordinator never releases post-
                    // finalize-decision); a still-live hold makes the refusal genuine.
                    let key_chirho = self.hold_key_chirho(saga_id_chirho, step_chirho, plan_chirho);
                    if journals_chirho
                        .active_hold_chirho(&plan_chirho.cluster_chirho, &key_chirho)
                        .is_some()
                    {
                        return Err(anyhow!(
                            "finalize of held step {step_chirho} refused unexpectedly: {error_chirho:?}"
                        ));
                    }
                    SagaStepEvidenceChirho::ResumedObservationChirho
                }
            };
            self.append_chirho(
                saga_id_chirho,
                SagaOpChirho::StepSettledChirho {
                    step_chirho,
                    evidence_chirho,
                },
            )?;
        }
        self.append_chirho(
            saga_id_chirho,
            SagaOpChirho::ClosedChirho {
                outcome_chirho: SagaOutcomeChirho::FinalizedChirho,
            },
        )?;
        Ok(())
    }

    /// Phase 2 (abort): sweep EVERY plan step with a release — including steps with no durable
    /// held record (the journal-held/saga-record-lost crash gap). UnknownEscrowHold on a step with
    /// a held record means the release itself landed pre-crash; on a step without one it means
    /// nothing was ever held. Both close the step.
    fn drive_release_phase_chirho(
        &self,
        journals_chirho: &mut dyn SagaJournalRouterChirho,
        saga_id_chirho: &DigestChirho,
        state_chirho: &SagaStateChirho,
    ) -> Result<()> {
        for (index_chirho, plan_chirho) in state_chirho.steps_chirho.iter().enumerate() {
            let step_chirho = (index_chirho + 1) as u32;
            if state_chirho.consumed_chirho.contains(&step_chirho) {
                continue;
            }
            // Release under the CURRENT continuation ref too (#5152 a3): a TTL-expiry compensation
            // releasing under a superseded ref is the quiet strand path — resolve current first.
            let continuation_chirho =
                self.current_continuation_chirho(journals_chirho, plan_chirho)?;
            let request_chirho = self.release_request_chirho(
                saga_id_chirho,
                step_chirho,
                plan_chirho,
                &continuation_chirho,
            );
            let outcome_chirho =
                journals_chirho.append_chirho(&plan_chirho.cluster_chirho, request_chirho);
            let evidence_chirho = match outcome_chirho {
                Ok(receipt_chirho) => Some(receipt_evidence_chirho(&receipt_chirho)),
                Err(JournalErrorChirho::AdmissionChirho {
                    reject_chirho: AdmissionRejectChirho::IdempotencyDuplicateChirho,
                }) => Some(SagaStepEvidenceChirho::ResumedObservationChirho),
                Err(JournalErrorChirho::AdmissionChirho {
                    reject_chirho: AdmissionRejectChirho::UnknownEscrowHoldChirho,
                }) => {
                    if state_chirho.held_chirho.contains(&step_chirho) {
                        // Held durably, unknown now ⇒ the release landed before the crash.
                        Some(SagaStepEvidenceChirho::ResumedObservationChirho)
                    } else {
                        // Never held (the hold never landed) — nothing to evidence.
                        None
                    }
                }
                Err(error_chirho) => {
                    let key_chirho = self.hold_key_chirho(saga_id_chirho, step_chirho, plan_chirho);
                    if journals_chirho
                        .active_hold_chirho(&plan_chirho.cluster_chirho, &key_chirho)
                        .is_some()
                    {
                        return Err(anyhow!(
                            "release of step {step_chirho} refused unexpectedly: {error_chirho:?}"
                        ));
                    }
                    // Quiescent in the journal: released pre-crash if durably held, moot if not.
                    if state_chirho.held_chirho.contains(&step_chirho) {
                        Some(SagaStepEvidenceChirho::ResumedObservationChirho)
                    } else {
                        None
                    }
                }
            };
            if let Some(evidence_chirho) = evidence_chirho {
                self.append_chirho(
                    saga_id_chirho,
                    SagaOpChirho::StepReleasedChirho {
                        step_chirho,
                        evidence_chirho,
                    },
                )?;
            }
        }
        self.append_chirho(
            saga_id_chirho,
            SagaOpChirho::ClosedChirho {
                outcome_chirho: SagaOutcomeChirho::CompensatedChirho,
            },
        )?;
        Ok(())
    }

    fn hold_request_chirho(
        &self,
        saga_id_chirho: &DigestChirho,
        step_chirho: u32,
        plan_chirho: &SagaStepPlanChirho,
    ) -> AppendRequestChirho {
        AppendRequestChirho {
            op_chirho: LedgerOpChirho::EscrowHoldChirho {
                control_chirho: self.control_chirho(saga_id_chirho, step_chirho),
            },
            // The hold uses the plan's ref (current at hold time; if already superseded the hold
            // refuses and the saga aborts, and the abort-path release re-resolves current).
            legs_chirho: vec![self.leg_chirho(
                plan_chirho,
                LegDeltaChirho::HoldChirho,
                &plan_chirho.kind_policy_ref_chirho,
            )],
            idempotency_key_chirho: self.step_idem_chirho(saga_id_chirho, step_chirho, "hold"),
            provenance_chirho: None,
            attribution_chirho: AttributionChirho::CauserChirho {
                principal_chirho: plan_chirho.owner_chirho.clone(),
            },
        }
    }

    /// Resolve the CURRENT continuation for a step's stable kind through the router (#5127/#5151).
    /// The stable kind comes from the coordinator's OWN durable plan — no caller ref exists; a
    /// kind that no longer resolves (unknown/retired) refuses so the settle/release fails with the
    /// hold LIVE rather than stranding it under a superseded ref.
    fn current_continuation_chirho(
        &self,
        journals_chirho: &dyn SagaJournalRouterChirho,
        plan_chirho: &SagaStepPlanChirho,
    ) -> Result<CurrentContinuationPolicyChirho> {
        journals_chirho
            .current_continuation_chirho(
                &plan_chirho.cluster_chirho,
                &AssetKindIdChirho(plan_chirho.kind_chirho.clone()),
            )
            .ok_or_else(|| {
                anyhow!(
                    "no current continuation for kind {} — refusing to settle, hold stays live",
                    plan_chirho.kind_chirho
                )
            })
    }

    fn release_request_chirho(
        &self,
        saga_id_chirho: &DigestChirho,
        step_chirho: u32,
        plan_chirho: &SagaStepPlanChirho,
        continuation_chirho: &CurrentContinuationPolicyChirho,
    ) -> AppendRequestChirho {
        AppendRequestChirho {
            op_chirho: LedgerOpChirho::EscrowReleaseChirho {
                control_chirho: self.control_chirho(saga_id_chirho, step_chirho),
            },
            legs_chirho: vec![self.leg_chirho(
                plan_chirho,
                LegDeltaChirho::ReleaseChirho,
                &continuation_chirho.kind_policy_ref_chirho,
            )],
            idempotency_key_chirho: self.step_idem_chirho(saga_id_chirho, step_chirho, "release"),
            provenance_chirho: None,
            attribution_chirho: AttributionChirho::CauserChirho {
                principal_chirho: plan_chirho.owner_chirho.clone(),
            },
        }
    }

    fn finalize_request_chirho(
        &self,
        saga_id_chirho: &DigestChirho,
        step_chirho: u32,
        plan_chirho: &SagaStepPlanChirho,
        continuation_chirho: &CurrentContinuationPolicyChirho,
    ) -> Result<AppendRequestChirho> {
        // The CURRENT settlement owner (the CF2 prospective-settlement sub-ruling): a None
        // settlement owner refuses so the hold stays live rather than crediting nowhere.
        let settlement_owner_chirho = continuation_chirho
            .policy_chirho
            .settlement_owner_chirho
            .clone()
            .ok_or_else(|| {
                anyhow!(
                    "current billing-kind policy for {} has no settlement owner",
                    plan_chirho.kind_chirho
                )
            })?;
        let mut settlement_leg_chirho = self.leg_chirho(
            plan_chirho,
            LegDeltaChirho::CreditChirho,
            &continuation_chirho.kind_policy_ref_chirho,
        );
        settlement_leg_chirho.account_chirho = LogIdChirho::new_chirho(
            settlement_owner_chirho.as_str(),
            plan_chirho.kind_chirho.as_str(),
        );
        Ok(AppendRequestChirho {
            op_chirho: LedgerOpChirho::EscrowFinalizeChirho {
                control_chirho: self.control_chirho(saga_id_chirho, step_chirho),
            },
            legs_chirho: vec![
                self.leg_chirho(
                    plan_chirho,
                    LegDeltaChirho::FinalizeChirho,
                    &continuation_chirho.kind_policy_ref_chirho,
                ),
                settlement_leg_chirho,
            ],
            idempotency_key_chirho: self.step_idem_chirho(saga_id_chirho, step_chirho, "finalize"),
            provenance_chirho: None,
            attribution_chirho: AttributionChirho::CauserChirho {
                principal_chirho: plan_chirho.owner_chirho.clone(),
            },
        })
    }

    fn leg_chirho(
        &self,
        plan_chirho: &SagaStepPlanChirho,
        delta_chirho: LegDeltaChirho,
        kind_policy_ref_chirho: &cairn_ledger_model_chirho::ids_chirho::AssetKindRefChirho,
    ) -> AppendLegRequestChirho {
        AppendLegRequestChirho {
            account_chirho: LogIdChirho::new_chirho(
                plan_chirho.owner_chirho.as_str(),
                plan_chirho.kind_chirho.as_str(),
            ),
            kind_policy_ref_chirho: kind_policy_ref_chirho.clone(),
            delta_chirho,
            amount_chirho: plan_chirho.amount_chirho,
            counterpart_chirho: None,
        }
    }

    fn control_chirho(
        &self,
        saga_id_chirho: &DigestChirho,
        step_chirho: u32,
    ) -> EscrowControlChirho {
        EscrowControlChirho {
            saga_id_chirho: saga_id_chirho.clone(),
            step_chirho,
        }
    }

    fn hold_key_chirho(
        &self,
        saga_id_chirho: &DigestChirho,
        step_chirho: u32,
        plan_chirho: &SagaStepPlanChirho,
    ) -> EscrowHoldKeyChirho {
        EscrowHoldKeyChirho {
            account_chirho: LogIdChirho::new_chirho(
                plan_chirho.owner_chirho.as_str(),
                plan_chirho.kind_chirho.as_str(),
            ),
            saga_id_chirho: saga_id_chirho.clone(),
            step_chirho,
        }
    }

    /// Deterministic per-(saga, step, op) journal idempotency key — a crash-retried append is the
    /// SAME request, so the journal's idempotency window closes the exactly-once gap the escrow
    /// laws don't already close.
    fn step_idem_chirho(
        &self,
        saga_id_chirho: &DigestChirho,
        step_chirho: u32,
        op_chirho: &str,
    ) -> String {
        format!(
            "saga-{}-step-{step_chirho}-{op_chirho}-chirho",
            &saga_id_chirho.0[..16.min(saga_id_chirho.0.len())]
        )
    }

    fn append_chirho(&self, saga_id_chirho: &DigestChirho, op_chirho: SagaOpChirho) -> Result<()> {
        append_saga_op_chirho(
            self.storage_chirho,
            self.root_chirho,
            &self.path_chirho,
            &self.saga_log_id_chirho,
            saga_id_chirho,
            op_chirho,
        )?;
        Ok(())
    }

    fn load_state_chirho(&self, saga_id_chirho: &DigestChirho) -> Result<SagaStateChirho> {
        let loaded_chirho = load_saga_log_chirho(
            self.storage_chirho,
            self.root_chirho,
            &self.path_chirho,
            &self.saga_log_id_chirho,
        )?;
        loaded_chirho
            .sagas_chirho
            .get(saga_id_chirho)
            .cloned()
            .ok_or_else(|| anyhow!("saga {} missing after append", saga_id_chirho.0))
    }
}

/// The §12 canonical lock coordinate: the domain-separated digest of the step's account-log id.
/// Sagas acquire holds in ASCENDING digest order — the no-deadlock law the lockorder model proves;
/// the digest (not the raw tuple) is the frozen coordinate, uniform and prefix-bias-free. Fields
/// are LENGTH-PREFIX framed (#5042 — a separator splice like cluster "a/b" + owner "c" vs "a" +
/// "b/c" must never collide: equal digests would tie-break by per-saga insertion order and the
/// total-order deadlock argument loses its premise).
pub fn step_lock_digest_chirho(step_chirho: &SagaStepPlanChirho) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(b"cairn-lock-order-v1-chirho:");
    for field_chirho in [
        step_chirho.cluster_chirho.0.as_str(),
        step_chirho.owner_chirho.as_str(),
        step_chirho.kind_chirho.as_str(),
    ] {
        hasher_chirho.update(&(field_chirho.len() as u64).to_be_bytes());
        hasher_chirho.update(field_chirho.as_bytes());
    }
    hasher_chirho.finalize().to_hex().to_string()
}

/// Σ over one journal's verified head states: net units per kind COUNTING HELD (held value is
/// neither destroyed nor spendable — the conservation cut the crash matrix asserts at every
/// boundary). Pure helper over the read-only getter.
pub fn net_units_by_kind_chirho(
    head_states_chirho: &std::collections::BTreeMap<
        cairn_ledger_model_chirho::ids_chirho::AccountIdChirho,
        cairn_ledger_model_chirho::record_chirho::LegPostStateChirho,
    >,
) -> std::collections::BTreeMap<String, i128> {
    let mut sums_chirho = std::collections::BTreeMap::new();
    for (account_chirho, post_chirho) in head_states_chirho {
        let net_chirho = i128::from(post_chirho.credits_total_chirho)
            - i128::from(post_chirho.debits_total_chirho);
        *sums_chirho
            .entry(account_chirho.kind_id_chirho.0.clone())
            .or_insert(0_i128) += net_chirho;
    }
    sums_chirho
}

/// Guard rail: this increment's plans must not carry counterpart claims — the x-cluster row stays
/// fail-closed until the F3 verifier lands (#4901 c scope line). The type system already prevents
/// it (plans build legs without counterparts); this marker documents the boundary for reviewers.
pub const X_CLUSTER_ROW_CLOSED_CHIRHO: &str =
    "counterpart/x-cluster settlement stays fail-closed until the F3 finality verifier increment";
