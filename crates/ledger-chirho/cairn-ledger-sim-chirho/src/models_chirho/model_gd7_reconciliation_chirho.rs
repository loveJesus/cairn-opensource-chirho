// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! GD7 deposed-fork reconciliation proof.
//!
//! Workflow contract: `spec-chirho/workflows-chirho/distributed-ha-chirho/`
//! `cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.
//!
//! This model starts at the point Model D deliberately stops: a higher-term winner exists while an
//! old leader can still emit bounded local-fork effects before observing the election. Observation
//! holds the node; a content-addressed losing manifest is sealed; the local served view adopts the
//! winner without erasing losing evidence; and only winner-authorized, one-per-original
//! compensations can make the read replica converge. A missing automatic inverse remains held.
//!
//! Fixed arrays make every transition O(1). The runtime design processes a losing suffix in bounded
//! pages: O(losing suffix) total work, O(page) memory, and no global-history or global-tenant scan.
//! This proof does not implement the runtime reconciler or prove election safety.
//!
//! **Why this proof is not vacuous, and what must not be weakened.** A bounded model that stops
//! exploring stays green on every `always` property, so "all laws hold" is worth nothing on its own.
//! Two independent reachability floors carry it, both confirmed by observation (2026-07-25) by
//! deleting the election action so the space collapsed to the initial phase:
//! - the two `sometimes` witnesses below require the joined crash-resumable reconcile and the manual
//!   hold to be actually REACHED, and stateright fails a `sometimes` that is never satisfied;
//! - every mutation test additionally asserts its specific violation is DISCOVERABLE, so each one
//!   doubles as a per-law reachability floor.
//!
//! Under the planted collapse both fired: the exhaustive test failed inside stateright's checker and
//! all NINE mutation tests failed their discovery assert. (Re-measured 2026-07-27 under an
//! anchor-asserted, diff-asserted collapse: baseline 11/11 green, collapsed 0 passed and
//! 11 failed — nine mutation tests plus both witness tests. An earlier revision said "seven",
//! which matches no run boundary over this file; it understated the evidence.) So do NOT weaken
//! `assert_mutation_reddens_chirho` into a bare property inversion — the discovery assert is what
//! makes the floors per-law. A state-count floor is deliberately absent: it would be weaker, since
//! any 70 junk states satisfy a count while only real ones satisfy these.
//!
//! The GD7-8 proof is a disjoint sidecar state machine below. It does not alter the GD7-1..7 state
//! or transitions. The sidecar models the cross-process cure as durable sink state: a persistent
//! highest-accepted winner term is checked inside the append transition before either a provider
//! call or journal append can occur. It does not model an opaque Rust mint, a production sink, or a
//! hosted drill.

use stateright::{Model, Property};

const NUM_EFFECTS_CHIRHO: usize = 2;
const DEPOSED_TERM_CHIRHO: u64 = 1;
const WINNER_TERM_CHIRHO: u64 = 2;
const FORK_ANCHOR_DIGEST_CHIRHO: u64 = 11;
const WINNER_BASE_DIGEST_CHIRHO: u64 = 22;
const ALL_EFFECTS_MASK_CHIRHO: u8 = (1_u8 << NUM_EFFECTS_CHIRHO) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ReconciliationPhaseChirho {
    OldAuthorityChirho,
    ForkingChirho,
    ObservedHeldChirho,
    PlanSealedChirho,
    AdoptedHeldChirho,
    HeldManualChirho,
    ConvergedReadReplicaChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StateGd7Chirho {
    phase_chirho: ReconciliationPhaseChirho,
    writer_enabled_chirho: bool,
    winner_term_chirho: u64,
    local_term_chirho: u64,
    winner_base_digest_chirho: u64,
    local_base_digest_chirho: u64,
    fork_anchor_digest_chirho: u64,
    losing_tail_digest_chirho: u64,
    sealed_losing_tail_digest_chirho: u64,
    losing_effect_mask_chirho: u8,
    sealed_manifest_mask_chirho: u8,
    plan_mask_chirho: u8,
    winner_receipt_mask_chirho: u8,
    local_receipt_mask_chirho: u8,
    manual_obligation_mask_chirho: u8,
    receipt_count_chirho: [u8; NUM_EFFECTS_CHIRHO],
    receipt_term_chirho: [Option<u64>; NUM_EFFECTS_CHIRHO],
    external_delta_chirho: i8,
    losing_evidence_retained_chirho: bool,
    restart_count_chirho: u8,
    crashed_after_partial_compensation_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ActionGd7Chirho {
    ElectHigherTermChirho,
    EmitLosingEffectChirho {
        effect_chirho: usize,
    },
    ObserveHigherTermChirho,
    SealManifestChirho,
    AdoptWinnerChirho,
    CompensateChirho {
        effect_chirho: usize,
    },
    /// A compensation that was ATTEMPTED and REFUSED — the provider said no. GD7-3 asserts a
    /// canonical compensation EXISTS and is unique; it says nothing about whether it SUCCEEDS, and
    /// for an irreversible external effect that is the whole problem. A reverse transfer can fail on
    /// a closed account, an insufficient balance, a provider refusal, or a recipient who already
    /// withdrew. Value has left, the compensation is defined, and it did not happen.
    CompensationRefusedChirho {
        effect_chirho: usize,
    },
    FollowWinnerChirho,
    CrashRestartChirho,
    CompleteChirho,
}

/// All `*_law_chirho` fields are TRUE in the lawful model configuration. One mutation test disables
/// each law; the production protocol remains explicitly unbuilt.
/// `manual_effect_chirho` is a scenario knob: that effect has no reviewed automatic inverse and
/// must move to the durable manual hold rather than converge.
pub struct ModelGd7Chirho {
    pub hold_on_observation_law_chirho: bool,
    pub exact_obligation_law_chirho: bool,
    pub authoritative_integrity_law_chirho: bool,
    pub evidence_retention_law_chirho: bool,
    pub winner_authorization_law_chirho: bool,
    pub compensation_idempotency_law_chirho: bool,
    pub compensation_conservation_law_chirho: bool,
    pub crash_progress_law_chirho: bool,
    pub complete_only_when_reconciled_law_chirho: bool,
    pub manual_effect_chirho: Option<usize>,
}

impl ModelGd7Chirho {
    fn bit_chirho(effect_chirho: usize) -> Option<u8> {
        (effect_chirho < NUM_EFFECTS_CHIRHO).then(|| 1_u8 << effect_chirho)
    }

    fn receipt_mask_from_counts_chirho(state_chirho: &StateGd7Chirho) -> u8 {
        state_chirho.receipt_count_chirho.iter().enumerate().fold(
            0_u8,
            |mask_chirho, (effect_chirho, count_chirho)| {
                if *count_chirho > 0 {
                    mask_chirho | (1_u8 << effect_chirho)
                } else {
                    mask_chirho
                }
            },
        )
    }

    fn receipt_total_chirho(state_chirho: &StateGd7Chirho) -> i8 {
        state_chirho
            .receipt_count_chirho
            .iter()
            .map(|count_chirho| *count_chirho as i8)
            .sum()
    }

    fn is_held_phase_chirho(phase_chirho: ReconciliationPhaseChirho) -> bool {
        matches!(
            phase_chirho,
            ReconciliationPhaseChirho::ObservedHeldChirho
                | ReconciliationPhaseChirho::PlanSealedChirho
                | ReconciliationPhaseChirho::AdoptedHeldChirho
                | ReconciliationPhaseChirho::HeldManualChirho
                | ReconciliationPhaseChirho::ConvergedReadReplicaChirho
        )
    }

    fn has_sealed_plan_chirho(phase_chirho: ReconciliationPhaseChirho) -> bool {
        matches!(
            phase_chirho,
            ReconciliationPhaseChirho::PlanSealedChirho
                | ReconciliationPhaseChirho::AdoptedHeldChirho
                | ReconciliationPhaseChirho::HeldManualChirho
                | ReconciliationPhaseChirho::ConvergedReadReplicaChirho
        )
    }

    fn has_adopted_chirho(phase_chirho: ReconciliationPhaseChirho) -> bool {
        matches!(
            phase_chirho,
            ReconciliationPhaseChirho::AdoptedHeldChirho
                | ReconciliationPhaseChirho::HeldManualChirho
                | ReconciliationPhaseChirho::ConvergedReadReplicaChirho
        )
    }

    fn exact_obligations_chirho(state_chirho: &StateGd7Chirho) -> bool {
        if !Self::has_sealed_plan_chirho(state_chirho.phase_chirho) {
            return true;
        }
        state_chirho.losing_evidence_retained_chirho
            && state_chirho.sealed_losing_tail_digest_chirho
                == state_chirho.losing_tail_digest_chirho
            && state_chirho.sealed_manifest_mask_chirho == state_chirho.losing_effect_mask_chirho
            && state_chirho.plan_mask_chirho == state_chirho.losing_effect_mask_chirho
    }

    fn compensation_is_authorized_once_chirho(state_chirho: &StateGd7Chirho) -> bool {
        (0..NUM_EFFECTS_CHIRHO).all(|effect_chirho| {
            let bit_chirho = 1_u8 << effect_chirho;
            let count_chirho = state_chirho.receipt_count_chirho[effect_chirho];
            count_chirho <= 1
                && (count_chirho == 0
                    || (state_chirho.losing_effect_mask_chirho & bit_chirho != 0
                        && state_chirho.plan_mask_chirho & bit_chirho != 0
                        && state_chirho.receipt_term_chirho[effect_chirho]
                            == Some(state_chirho.winner_term_chirho)))
                && (count_chirho > 0 || state_chirho.receipt_term_chirho[effect_chirho].is_none())
        })
    }

    fn compensation_conserves_chirho(state_chirho: &StateGd7Chirho) -> bool {
        let expected_delta_chirho = state_chirho.losing_effect_mask_chirho.count_ones() as i8
            - Self::receipt_total_chirho(state_chirho);
        state_chirho.external_delta_chirho == expected_delta_chirho
            && state_chirho.external_delta_chirho >= 0
    }

    fn durable_progress_chirho(state_chirho: &StateGd7Chirho) -> bool {
        state_chirho.winner_receipt_mask_chirho
            == Self::receipt_mask_from_counts_chirho(state_chirho)
            && state_chirho.local_receipt_mask_chirho & !state_chirho.winner_receipt_mask_chirho
                == 0
    }

    fn converged_lawfully_chirho(state_chirho: &StateGd7Chirho) -> bool {
        if !Self::has_adopted_chirho(state_chirho.phase_chirho) {
            return true;
        }
        let adopted_chirho = state_chirho.local_term_chirho == state_chirho.winner_term_chirho
            && state_chirho.local_base_digest_chirho == state_chirho.winner_base_digest_chirho;
        if state_chirho.phase_chirho != ReconciliationPhaseChirho::ConvergedReadReplicaChirho {
            return adopted_chirho;
        }
        adopted_chirho
            && state_chirho.manual_obligation_mask_chirho == 0
            && state_chirho.winner_receipt_mask_chirho == state_chirho.plan_mask_chirho
            && state_chirho.local_receipt_mask_chirho == state_chirho.winner_receipt_mask_chirho
            && state_chirho.external_delta_chirho == 0
            && state_chirho.losing_evidence_retained_chirho
    }

    fn joined_witness_chirho(state_chirho: &StateGd7Chirho) -> bool {
        state_chirho.phase_chirho == ReconciliationPhaseChirho::ConvergedReadReplicaChirho
            && state_chirho.losing_effect_mask_chirho == ALL_EFFECTS_MASK_CHIRHO
            && state_chirho.sealed_manifest_mask_chirho == ALL_EFFECTS_MASK_CHIRHO
            && state_chirho.plan_mask_chirho == ALL_EFFECTS_MASK_CHIRHO
            && state_chirho.winner_receipt_mask_chirho == ALL_EFFECTS_MASK_CHIRHO
            && state_chirho.local_receipt_mask_chirho == ALL_EFFECTS_MASK_CHIRHO
            && state_chirho.restart_count_chirho == 1
            && state_chirho.crashed_after_partial_compensation_chirho
            && state_chirho.external_delta_chirho == 0
    }
}

impl Model for ModelGd7Chirho {
    type State = StateGd7Chirho;
    type Action = ActionGd7Chirho;

    fn init_states(&self) -> Vec<Self::State> {
        vec![StateGd7Chirho {
            phase_chirho: ReconciliationPhaseChirho::OldAuthorityChirho,
            writer_enabled_chirho: true,
            winner_term_chirho: DEPOSED_TERM_CHIRHO,
            local_term_chirho: DEPOSED_TERM_CHIRHO,
            winner_base_digest_chirho: WINNER_BASE_DIGEST_CHIRHO,
            local_base_digest_chirho: FORK_ANCHOR_DIGEST_CHIRHO,
            fork_anchor_digest_chirho: FORK_ANCHOR_DIGEST_CHIRHO,
            losing_tail_digest_chirho: FORK_ANCHOR_DIGEST_CHIRHO,
            sealed_losing_tail_digest_chirho: 0,
            losing_effect_mask_chirho: 0,
            sealed_manifest_mask_chirho: 0,
            plan_mask_chirho: 0,
            winner_receipt_mask_chirho: 0,
            local_receipt_mask_chirho: 0,
            manual_obligation_mask_chirho: 0,
            receipt_count_chirho: [0; NUM_EFFECTS_CHIRHO],
            receipt_term_chirho: [None; NUM_EFFECTS_CHIRHO],
            external_delta_chirho: 0,
            losing_evidence_retained_chirho: false,
            restart_count_chirho: 0,
            crashed_after_partial_compensation_chirho: false,
        }]
    }

    fn actions(&self, state_chirho: &Self::State, actions_chirho: &mut Vec<Self::Action>) {
        match state_chirho.phase_chirho {
            ReconciliationPhaseChirho::OldAuthorityChirho => {
                actions_chirho.push(ActionGd7Chirho::ElectHigherTermChirho);
            }
            ReconciliationPhaseChirho::ForkingChirho => {
                for effect_chirho in 0..NUM_EFFECTS_CHIRHO {
                    let bit_chirho = 1_u8 << effect_chirho;
                    if state_chirho.losing_effect_mask_chirho & bit_chirho == 0 {
                        actions_chirho
                            .push(ActionGd7Chirho::EmitLosingEffectChirho { effect_chirho });
                    }
                }
                actions_chirho.push(ActionGd7Chirho::ObserveHigherTermChirho);
            }
            ReconciliationPhaseChirho::ObservedHeldChirho => {
                actions_chirho.push(ActionGd7Chirho::SealManifestChirho);
            }
            ReconciliationPhaseChirho::PlanSealedChirho => {
                actions_chirho.push(ActionGd7Chirho::AdoptWinnerChirho);
            }
            ReconciliationPhaseChirho::AdoptedHeldChirho => {
                for effect_chirho in 0..NUM_EFFECTS_CHIRHO {
                    let bit_chirho = 1_u8 << effect_chirho;
                    if state_chirho.plan_mask_chirho & bit_chirho != 0
                        && (state_chirho.receipt_count_chirho[effect_chirho] == 0
                            || (!self.compensation_idempotency_law_chirho
                                && state_chirho.receipt_count_chirho[effect_chirho] < 2))
                    {
                        actions_chirho.push(ActionGd7Chirho::CompensateChirho { effect_chirho });
                        // The adversarial twin of the line above: every compensation the model may
                        // attempt, it may also have REFUSED.
                        actions_chirho
                            .push(ActionGd7Chirho::CompensationRefusedChirho { effect_chirho });
                    }
                }
                if state_chirho.local_receipt_mask_chirho != state_chirho.winner_receipt_mask_chirho
                {
                    actions_chirho.push(ActionGd7Chirho::FollowWinnerChirho);
                }
                actions_chirho.push(ActionGd7Chirho::CompleteChirho);
            }
            ReconciliationPhaseChirho::HeldManualChirho
            | ReconciliationPhaseChirho::ConvergedReadReplicaChirho => {}
        }
        if Self::is_held_phase_chirho(state_chirho.phase_chirho)
            && state_chirho.restart_count_chirho == 0
        {
            actions_chirho.push(ActionGd7Chirho::CrashRestartChirho);
        }
    }

    fn next_state(
        &self,
        last_chirho: &Self::State,
        action_chirho: Self::Action,
    ) -> Option<Self::State> {
        let mut next_chirho = last_chirho.clone();
        match action_chirho {
            ActionGd7Chirho::ElectHigherTermChirho => {
                if last_chirho.phase_chirho != ReconciliationPhaseChirho::OldAuthorityChirho {
                    return None;
                }
                next_chirho.phase_chirho = ReconciliationPhaseChirho::ForkingChirho;
                next_chirho.winner_term_chirho = WINNER_TERM_CHIRHO;
            }
            ActionGd7Chirho::EmitLosingEffectChirho { effect_chirho } => {
                if last_chirho.phase_chirho != ReconciliationPhaseChirho::ForkingChirho
                    || !last_chirho.writer_enabled_chirho
                {
                    return None;
                }
                let bit_chirho = Self::bit_chirho(effect_chirho)?;
                if last_chirho.losing_effect_mask_chirho & bit_chirho != 0 {
                    return None;
                }
                next_chirho.losing_effect_mask_chirho |= bit_chirho;
                next_chirho.losing_tail_digest_chirho =
                    next_chirho.losing_tail_digest_chirho.checked_add(1)?;
                next_chirho.external_delta_chirho =
                    next_chirho.external_delta_chirho.checked_add(1)?;
            }
            ActionGd7Chirho::ObserveHigherTermChirho => {
                if last_chirho.phase_chirho != ReconciliationPhaseChirho::ForkingChirho {
                    return None;
                }
                next_chirho.phase_chirho = ReconciliationPhaseChirho::ObservedHeldChirho;
                if self.hold_on_observation_law_chirho {
                    next_chirho.writer_enabled_chirho = false;
                }
            }
            ActionGd7Chirho::SealManifestChirho => {
                if last_chirho.phase_chirho != ReconciliationPhaseChirho::ObservedHeldChirho {
                    return None;
                }
                next_chirho.phase_chirho = ReconciliationPhaseChirho::PlanSealedChirho;
                next_chirho.sealed_losing_tail_digest_chirho =
                    last_chirho.losing_tail_digest_chirho;
                next_chirho.sealed_manifest_mask_chirho = last_chirho.losing_effect_mask_chirho;
                next_chirho.plan_mask_chirho = if self.exact_obligation_law_chirho {
                    last_chirho.losing_effect_mask_chirho
                } else {
                    last_chirho
                        .losing_effect_mask_chirho
                        .checked_sub(1)
                        .map_or(0, |prior_chirho| {
                            last_chirho.losing_effect_mask_chirho & prior_chirho
                        })
                };
                next_chirho.losing_evidence_retained_chirho = true;
            }
            ActionGd7Chirho::AdoptWinnerChirho => {
                if last_chirho.phase_chirho != ReconciliationPhaseChirho::PlanSealedChirho {
                    return None;
                }
                next_chirho.phase_chirho = ReconciliationPhaseChirho::AdoptedHeldChirho;
                if !self.authoritative_integrity_law_chirho {
                    next_chirho.winner_base_digest_chirho =
                        next_chirho.winner_base_digest_chirho.checked_add(1)?;
                }
                next_chirho.local_term_chirho = next_chirho.winner_term_chirho;
                next_chirho.local_base_digest_chirho = next_chirho.winner_base_digest_chirho;
                if !self.evidence_retention_law_chirho {
                    next_chirho.losing_evidence_retained_chirho = false;
                }
            }
            ActionGd7Chirho::CompensateChirho { effect_chirho } => {
                if last_chirho.phase_chirho != ReconciliationPhaseChirho::AdoptedHeldChirho {
                    return None;
                }
                let bit_chirho = Self::bit_chirho(effect_chirho)?;
                if last_chirho.plan_mask_chirho & bit_chirho == 0 {
                    return None;
                }
                if self.manual_effect_chirho == Some(effect_chirho) {
                    next_chirho.phase_chirho = ReconciliationPhaseChirho::HeldManualChirho;
                    next_chirho.manual_obligation_mask_chirho |= bit_chirho;
                    return Some(next_chirho);
                }
                let count_chirho = last_chirho.receipt_count_chirho[effect_chirho];
                if count_chirho > 0 && self.compensation_idempotency_law_chirho {
                    return None;
                }
                if count_chirho >= 2 {
                    return None;
                }
                next_chirho.receipt_count_chirho[effect_chirho] = count_chirho + 1;
                next_chirho.receipt_term_chirho[effect_chirho] =
                    Some(if self.winner_authorization_law_chirho {
                        last_chirho.winner_term_chirho
                    } else {
                        DEPOSED_TERM_CHIRHO
                    });
                next_chirho.winner_receipt_mask_chirho |= bit_chirho;
                if self.compensation_conservation_law_chirho {
                    next_chirho.external_delta_chirho =
                        next_chirho.external_delta_chirho.checked_sub(1)?;
                }
            }
            ActionGd7Chirho::CompensationRefusedChirho { effect_chirho } => {
                if last_chirho.phase_chirho != ReconciliationPhaseChirho::AdoptedHeldChirho {
                    return None;
                }
                let bit_chirho = Self::bit_chirho(effect_chirho)?;
                if last_chirho.plan_mask_chirho & bit_chirho == 0 {
                    return None;
                }
                if last_chirho.receipt_count_chirho[effect_chirho] > 0 {
                    return None; // already compensated; a refusal after success is not this case
                }
                // Deliberately touches NEITHER the receipt count NOR the external delta: nothing was
                // returned, so conservation must still see the value as outstanding. The node lands
                // in the manual-hold terminal state, which is what forbids convergence.
                next_chirho.phase_chirho = ReconciliationPhaseChirho::HeldManualChirho;
                next_chirho.manual_obligation_mask_chirho |= bit_chirho;
            }
            ActionGd7Chirho::FollowWinnerChirho => {
                if last_chirho.phase_chirho != ReconciliationPhaseChirho::AdoptedHeldChirho {
                    return None;
                }
                next_chirho.local_receipt_mask_chirho = last_chirho.winner_receipt_mask_chirho;
            }
            ActionGd7Chirho::CrashRestartChirho => {
                if !Self::is_held_phase_chirho(last_chirho.phase_chirho)
                    || last_chirho.restart_count_chirho != 0
                {
                    return None;
                }
                next_chirho.restart_count_chirho = 1;
                next_chirho.crashed_after_partial_compensation_chirho =
                    last_chirho.winner_receipt_mask_chirho != 0
                        && last_chirho.winner_receipt_mask_chirho != last_chirho.plan_mask_chirho;
                if !self.crash_progress_law_chirho && next_chirho.winner_receipt_mask_chirho != 0 {
                    next_chirho.winner_receipt_mask_chirho = 0;
                }
            }
            ActionGd7Chirho::CompleteChirho => {
                if last_chirho.phase_chirho != ReconciliationPhaseChirho::AdoptedHeldChirho {
                    return None;
                }
                let fully_reconciled_chirho = last_chirho.manual_obligation_mask_chirho == 0
                    && last_chirho.winner_receipt_mask_chirho == last_chirho.plan_mask_chirho
                    && last_chirho.local_receipt_mask_chirho
                        == last_chirho.winner_receipt_mask_chirho
                    && last_chirho.external_delta_chirho == 0;
                if self.complete_only_when_reconciled_law_chirho && !fully_reconciled_chirho {
                    return None;
                }
                next_chirho.phase_chirho = ReconciliationPhaseChirho::ConvergedReadReplicaChirho;
            }
        }
        Some(next_chirho)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::<Self>::always(
                "gd7-1-authoritative-branch-immutable-chirho",
                |_, state_chirho| {
                    state_chirho.winner_base_digest_chirho == WINNER_BASE_DIGEST_CHIRHO
                        && state_chirho.fork_anchor_digest_chirho == FORK_ANCHOR_DIGEST_CHIRHO
                },
            ),
            Property::<Self>::always(
                "gd7-2-exact-losing-obligations-chirho",
                |_, state_chirho| Self::exact_obligations_chirho(state_chirho),
            ),
            Property::<Self>::always(
                "gd7-3-conservation-through-reconciliation-chirho",
                |_, state_chirho| Self::compensation_conserves_chirho(state_chirho),
            ),
            Property::<Self>::always(
                "gd7-4-consume-once-winner-authorization-chirho",
                |_, state_chirho| Self::compensation_is_authorized_once_chirho(state_chirho),
            ),
            Property::<Self>::always("gd7-5-no-partial-authority-chirho", |_, state_chirho| {
                !Self::is_held_phase_chirho(state_chirho.phase_chirho)
                    || !state_chirho.writer_enabled_chirho
            }),
            Property::<Self>::always("gd7-crash-progress-is-durable-chirho", |_, state_chirho| {
                Self::durable_progress_chirho(state_chirho)
            }),
            Property::<Self>::always(
                "gd7-6-evidence-retention-and-convergence-chirho",
                |_, state_chirho| Self::converged_lawfully_chirho(state_chirho),
            ),
            Property::<Self>::always(
                "gd7-manual-obligation-stays-held-chirho",
                |_, state_chirho| {
                    state_chirho.phase_chirho != ReconciliationPhaseChirho::HeldManualChirho
                        || (state_chirho.manual_obligation_mask_chirho != 0
                            && !state_chirho.writer_enabled_chirho)
                },
            ),
            Property::<Self>::sometimes(
                "gd7-joined-crash-resumable-reconciliation-reachable-chirho",
                |model_chirho, state_chirho| {
                    model_chirho.manual_effect_chirho.is_some()
                        || Self::joined_witness_chirho(state_chirho)
                },
            ),
            // A REFUSED compensation must be REACHABLE and must leave the value outstanding while
            // holding the node. Gated on there being no configured manual effect, so the only way to
            // satisfy it is an attempted-and-refused compensation rather than the manual path — which
            // is what makes adding the refusal action non-vacuous rather than decorative.
            Property::<Self>::sometimes(
                "gd7-refused-compensation-holds-value-outstanding-chirho",
                |model_chirho, state_chirho| {
                    model_chirho.manual_effect_chirho.is_some()
                        || (state_chirho.phase_chirho
                            == ReconciliationPhaseChirho::HeldManualChirho
                            && state_chirho.manual_obligation_mask_chirho != 0
                            && state_chirho.external_delta_chirho > 0)
                },
            ),
            Property::<Self>::sometimes(
                "gd7-manual-hold-reachable-chirho",
                |model_chirho, state_chirho| {
                    model_chirho.manual_effect_chirho.is_none()
                        || state_chirho.phase_chirho == ReconciliationPhaseChirho::HeldManualChirho
                },
            ),
        ]
    }
}

const GD78_SEALED_PLAN_IDENTITY_CHIRHO: u64 = 41;
const GD78_FORWARD_EFFECT_KEY_CHIRHO: u64 = 51;
const GD78_COMPENSATION_EFFECT_KEY_CHIRHO: u64 = 52;
const GD78_TERMINAL_MARKER_CHIRHO: u64 = 61;
const GD78_SOURCE_SEQ_CHIRHO: u64 = 71;
const GD78_SOURCE_RECORD_DIGEST_CHIRHO: u64 = 81;
const GD78_REVOKED_WINNER_TERM_CHIRHO: u64 = WINNER_TERM_CHIRHO + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Gd78PhaseChirho {
    InitialChirho,
    CaseSealedChirho,
    ObligationReadyChirho,
    WinnerSignedChirho,
    FinishedChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Gd78ManifestMembershipChirho {
    InManifestChirho,
    NotInManifestChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Gd78TerminalDispositionChirho {
    NoTerminalChirho,
    CommittedFinalizeChirho,
    DefiniteNoEffectReleaseChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Gd78ObligationKindChirho {
    NoObligationChirho,
    CommittedOnLosingForkChirho,
    InDoubtHoldOnLosingForkChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Gd78EffectLineageChirho {
    ForwardChirho,
    CompensationOfCompensationChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Gd78BarrierChirho {
    LiveChirho,
    RevokedChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Gd78ObligationOriginChirho {
    NoneChirho,
    SealedPlanMintChirho,
    ConstructedChirho,
    DeserializedChirho,
    ForeignReconciliationChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Gd78OutcomeChirho {
    PendingChirho,
    ConsumedCompensationChirho,
    HeldInDoubtChirho,
    DefiniteNoEffectReleasedChirho,
    RefusedProvenanceChirho,
    RefusedSinkFenceChirho,
    SilentlySkippedLineageChirho,
    IncorrectlyHeldDefiniteReleaseChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Gd78ObligationIdentityChirho {
    sealed_plan_identity_chirho: u64,
    winner_reconciliation_term_chirho: u64,
    obligation_kind_chirho: Gd78ObligationKindChirho,
    effect_lineage_chirho: Gd78EffectLineageChirho,
    original_effect_key_chirho: Option<u64>,
    terminal_disposition_chirho: Gd78TerminalDispositionChirho,
    terminal_marker_chirho: Option<u64>,
    source_seq_chirho: u64,
    source_record_digest_chirho: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Gd78IdentityCoordinateChirho {
    SealedPlanIdentityChirho,
    WinnerReconciliationTermChirho,
    ObligationKindChirho,
    EffectLineageChirho,
    OriginalEffectKeyChirho,
    TerminalDispositionChirho,
    TerminalMarkerChirho,
    SourceSeqChirho,
    SourceRecordDigestChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct StateGd78Chirho {
    phase_chirho: Gd78PhaseChirho,
    manifest_membership_chirho: Gd78ManifestMembershipChirho,
    terminal_disposition_chirho: Gd78TerminalDispositionChirho,
    obligation_kind_chirho: Gd78ObligationKindChirho,
    effect_lineage_chirho: Gd78EffectLineageChirho,
    obligation_origin_chirho: Gd78ObligationOriginChirho,
    obligation_identity_chirho: Option<Gd78ObligationIdentityChirho>,
    winner_signature_term_chirho: Option<u64>,
    barrier_chirho: Gd78BarrierChirho,
    current_winner_term_chirho: u64,
    sink_highest_accepted_winner_term_chirho: u64,
    sink_restart_count_chirho: u8,
    provider_call_count_chirho: u8,
    journal_append_count_chirho: u8,
    outcome_chirho: Gd78OutcomeChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum ActionGd78Chirho {
    SealCaseChirho {
        manifest_membership_chirho: Gd78ManifestMembershipChirho,
        terminal_disposition_chirho: Gd78TerminalDispositionChirho,
        obligation_kind_chirho: Gd78ObligationKindChirho,
        effect_lineage_chirho: Gd78EffectLineageChirho,
    },
    MintBoundObligationChirho,
    ConstructObligationChirho,
    DeserializeObligationChirho,
    ReplayForeignObligationChirho,
    SignWithCurrentWinnerChirho,
    RevokeBarrierChirho,
    RestartSinkChirho,
    AppendAtSinkChirho,
    ApplyDefiniteNoEffectReleaseChirho,
}

/// GD7-8 is isolated from the GD7-1..7 model above. Every `*_law_chirho` field is true in the
/// lawful configuration; focused mutation tests disable exactly one binding or outcome rule.
struct ModelGd78Chirho {
    manifest_membership_law_chirho: bool,
    constructed_origin_law_chirho: bool,
    deserialized_origin_law_chirho: bool,
    foreign_origin_law_chirho: bool,
    sink_term_fence_law_chirho: bool,
    sink_term_persistence_law_chirho: bool,
    compensation_lineage_law_chirho: bool,
    definite_release_law_chirho: bool,
    ignored_identity_coordinate_chirho: Option<Gd78IdentityCoordinateChirho>,
}

impl ModelGd78Chirho {
    fn original_effect_key_chirho(lineage_chirho: Gd78EffectLineageChirho) -> Option<u64> {
        match lineage_chirho {
            Gd78EffectLineageChirho::ForwardChirho => Some(GD78_FORWARD_EFFECT_KEY_CHIRHO),
            Gd78EffectLineageChirho::CompensationOfCompensationChirho => {
                Some(GD78_COMPENSATION_EFFECT_KEY_CHIRHO)
            }
        }
    }

    fn expected_identity_chirho(state_chirho: &StateGd78Chirho) -> Gd78ObligationIdentityChirho {
        Gd78ObligationIdentityChirho {
            sealed_plan_identity_chirho: GD78_SEALED_PLAN_IDENTITY_CHIRHO,
            winner_reconciliation_term_chirho: WINNER_TERM_CHIRHO,
            obligation_kind_chirho: state_chirho.obligation_kind_chirho,
            effect_lineage_chirho: state_chirho.effect_lineage_chirho,
            original_effect_key_chirho: Self::original_effect_key_chirho(
                state_chirho.effect_lineage_chirho,
            ),
            terminal_disposition_chirho: state_chirho.terminal_disposition_chirho,
            terminal_marker_chirho: (state_chirho.terminal_disposition_chirho
                == Gd78TerminalDispositionChirho::CommittedFinalizeChirho)
                .then_some(GD78_TERMINAL_MARKER_CHIRHO),
            source_seq_chirho: GD78_SOURCE_SEQ_CHIRHO,
            source_record_digest_chirho: GD78_SOURCE_RECORD_DIGEST_CHIRHO,
        }
    }

    fn mutate_identity_chirho(
        &self,
        mut identity_chirho: Gd78ObligationIdentityChirho,
    ) -> Gd78ObligationIdentityChirho {
        match self.ignored_identity_coordinate_chirho {
            Some(Gd78IdentityCoordinateChirho::SealedPlanIdentityChirho) => {
                identity_chirho.sealed_plan_identity_chirho += 1;
            }
            Some(Gd78IdentityCoordinateChirho::WinnerReconciliationTermChirho) => {
                identity_chirho.winner_reconciliation_term_chirho = DEPOSED_TERM_CHIRHO;
            }
            Some(Gd78IdentityCoordinateChirho::ObligationKindChirho) => {
                identity_chirho.obligation_kind_chirho =
                    match identity_chirho.obligation_kind_chirho {
                        Gd78ObligationKindChirho::CommittedOnLosingForkChirho => {
                            Gd78ObligationKindChirho::InDoubtHoldOnLosingForkChirho
                        }
                        _ => Gd78ObligationKindChirho::CommittedOnLosingForkChirho,
                    };
            }
            Some(Gd78IdentityCoordinateChirho::EffectLineageChirho) => {
                identity_chirho.effect_lineage_chirho = match identity_chirho.effect_lineage_chirho
                {
                    Gd78EffectLineageChirho::ForwardChirho => {
                        Gd78EffectLineageChirho::CompensationOfCompensationChirho
                    }
                    Gd78EffectLineageChirho::CompensationOfCompensationChirho => {
                        Gd78EffectLineageChirho::ForwardChirho
                    }
                };
            }
            Some(Gd78IdentityCoordinateChirho::OriginalEffectKeyChirho) => {
                identity_chirho.original_effect_key_chirho = Some(99);
            }
            Some(Gd78IdentityCoordinateChirho::TerminalDispositionChirho) => {
                identity_chirho.terminal_disposition_chirho =
                    Gd78TerminalDispositionChirho::DefiniteNoEffectReleaseChirho;
            }
            Some(Gd78IdentityCoordinateChirho::TerminalMarkerChirho) => {
                identity_chirho.terminal_marker_chirho = Some(99);
            }
            Some(Gd78IdentityCoordinateChirho::SourceSeqChirho) => {
                identity_chirho.source_seq_chirho += 1;
            }
            Some(Gd78IdentityCoordinateChirho::SourceRecordDigestChirho) => {
                identity_chirho.source_record_digest_chirho += 1;
            }
            None => {}
        }
        identity_chirho
    }

    fn identity_coordinate_matches_chirho(
        &self,
        coordinate_chirho: Gd78IdentityCoordinateChirho,
        actual_chirho: Gd78ObligationIdentityChirho,
        expected_chirho: Gd78ObligationIdentityChirho,
    ) -> bool {
        if self.ignored_identity_coordinate_chirho == Some(coordinate_chirho) {
            return true;
        }
        match coordinate_chirho {
            Gd78IdentityCoordinateChirho::SealedPlanIdentityChirho => {
                actual_chirho.sealed_plan_identity_chirho
                    == expected_chirho.sealed_plan_identity_chirho
            }
            Gd78IdentityCoordinateChirho::WinnerReconciliationTermChirho => {
                actual_chirho.winner_reconciliation_term_chirho
                    == expected_chirho.winner_reconciliation_term_chirho
            }
            Gd78IdentityCoordinateChirho::ObligationKindChirho => {
                actual_chirho.obligation_kind_chirho == expected_chirho.obligation_kind_chirho
            }
            Gd78IdentityCoordinateChirho::EffectLineageChirho => {
                actual_chirho.effect_lineage_chirho == expected_chirho.effect_lineage_chirho
            }
            Gd78IdentityCoordinateChirho::OriginalEffectKeyChirho => {
                actual_chirho.original_effect_key_chirho
                    == expected_chirho.original_effect_key_chirho
            }
            Gd78IdentityCoordinateChirho::TerminalDispositionChirho => {
                actual_chirho.terminal_disposition_chirho
                    == expected_chirho.terminal_disposition_chirho
            }
            Gd78IdentityCoordinateChirho::TerminalMarkerChirho => {
                actual_chirho.terminal_marker_chirho == expected_chirho.terminal_marker_chirho
            }
            Gd78IdentityCoordinateChirho::SourceSeqChirho => {
                actual_chirho.source_seq_chirho == expected_chirho.source_seq_chirho
            }
            Gd78IdentityCoordinateChirho::SourceRecordDigestChirho => {
                actual_chirho.source_record_digest_chirho
                    == expected_chirho.source_record_digest_chirho
            }
        }
    }

    fn identity_is_accepted_chirho(
        &self,
        state_chirho: &StateGd78Chirho,
        actual_chirho: Gd78ObligationIdentityChirho,
    ) -> bool {
        let expected_chirho = Self::expected_identity_chirho(state_chirho);
        [
            Gd78IdentityCoordinateChirho::SealedPlanIdentityChirho,
            Gd78IdentityCoordinateChirho::WinnerReconciliationTermChirho,
            Gd78IdentityCoordinateChirho::ObligationKindChirho,
            Gd78IdentityCoordinateChirho::EffectLineageChirho,
            Gd78IdentityCoordinateChirho::OriginalEffectKeyChirho,
            Gd78IdentityCoordinateChirho::TerminalDispositionChirho,
            Gd78IdentityCoordinateChirho::TerminalMarkerChirho,
            Gd78IdentityCoordinateChirho::SourceSeqChirho,
            Gd78IdentityCoordinateChirho::SourceRecordDigestChirho,
        ]
        .into_iter()
        .all(|coordinate_chirho| {
            self.identity_coordinate_matches_chirho(
                coordinate_chirho,
                actual_chirho,
                expected_chirho,
            )
        })
    }

    fn origin_is_accepted_chirho(&self, origin_chirho: Gd78ObligationOriginChirho) -> bool {
        match origin_chirho {
            Gd78ObligationOriginChirho::SealedPlanMintChirho => true,
            Gd78ObligationOriginChirho::ConstructedChirho => !self.constructed_origin_law_chirho,
            Gd78ObligationOriginChirho::DeserializedChirho => !self.deserialized_origin_law_chirho,
            Gd78ObligationOriginChirho::ForeignReconciliationChirho => {
                !self.foreign_origin_law_chirho
            }
            Gd78ObligationOriginChirho::NoneChirho => false,
        }
    }

    fn side_effected_chirho(state_chirho: &StateGd78Chirho) -> bool {
        state_chirho.provider_call_count_chirho > 0 || state_chirho.journal_append_count_chirho > 0
    }

    fn binding_property_chirho(
        state_chirho: &StateGd78Chirho,
        coordinate_chirho: Gd78IdentityCoordinateChirho,
    ) -> bool {
        if !Self::side_effected_chirho(state_chirho) {
            return true;
        }
        let Some(actual_chirho) = state_chirho.obligation_identity_chirho else {
            return false;
        };
        let expected_chirho = Self::expected_identity_chirho(state_chirho);
        match coordinate_chirho {
            Gd78IdentityCoordinateChirho::SealedPlanIdentityChirho => {
                actual_chirho.sealed_plan_identity_chirho
                    == expected_chirho.sealed_plan_identity_chirho
            }
            Gd78IdentityCoordinateChirho::WinnerReconciliationTermChirho => {
                actual_chirho.winner_reconciliation_term_chirho
                    == expected_chirho.winner_reconciliation_term_chirho
            }
            Gd78IdentityCoordinateChirho::ObligationKindChirho => {
                actual_chirho.obligation_kind_chirho == expected_chirho.obligation_kind_chirho
            }
            Gd78IdentityCoordinateChirho::EffectLineageChirho => {
                actual_chirho.effect_lineage_chirho == expected_chirho.effect_lineage_chirho
            }
            Gd78IdentityCoordinateChirho::OriginalEffectKeyChirho => {
                actual_chirho.original_effect_key_chirho
                    == expected_chirho.original_effect_key_chirho
            }
            Gd78IdentityCoordinateChirho::TerminalDispositionChirho => {
                actual_chirho.terminal_disposition_chirho
                    == expected_chirho.terminal_disposition_chirho
            }
            Gd78IdentityCoordinateChirho::TerminalMarkerChirho => {
                actual_chirho.terminal_marker_chirho == expected_chirho.terminal_marker_chirho
            }
            Gd78IdentityCoordinateChirho::SourceSeqChirho => {
                actual_chirho.source_seq_chirho == expected_chirho.source_seq_chirho
            }
            Gd78IdentityCoordinateChirho::SourceRecordDigestChirho => {
                actual_chirho.source_record_digest_chirho
                    == expected_chirho.source_record_digest_chirho
            }
        }
    }

    fn seal_actions_chirho(actions_chirho: &mut Vec<ActionGd78Chirho>) {
        for effect_lineage_chirho in [
            Gd78EffectLineageChirho::ForwardChirho,
            Gd78EffectLineageChirho::CompensationOfCompensationChirho,
        ] {
            actions_chirho.push(ActionGd78Chirho::SealCaseChirho {
                manifest_membership_chirho: Gd78ManifestMembershipChirho::InManifestChirho,
                terminal_disposition_chirho: Gd78TerminalDispositionChirho::CommittedFinalizeChirho,
                obligation_kind_chirho: Gd78ObligationKindChirho::CommittedOnLosingForkChirho,
                effect_lineage_chirho,
            });
            actions_chirho.push(ActionGd78Chirho::SealCaseChirho {
                manifest_membership_chirho: Gd78ManifestMembershipChirho::InManifestChirho,
                terminal_disposition_chirho: Gd78TerminalDispositionChirho::NoTerminalChirho,
                obligation_kind_chirho: Gd78ObligationKindChirho::InDoubtHoldOnLosingForkChirho,
                effect_lineage_chirho,
            });
            actions_chirho.push(ActionGd78Chirho::SealCaseChirho {
                manifest_membership_chirho: Gd78ManifestMembershipChirho::InManifestChirho,
                terminal_disposition_chirho:
                    Gd78TerminalDispositionChirho::DefiniteNoEffectReleaseChirho,
                obligation_kind_chirho: Gd78ObligationKindChirho::NoObligationChirho,
                effect_lineage_chirho,
            });
            actions_chirho.push(ActionGd78Chirho::SealCaseChirho {
                manifest_membership_chirho: Gd78ManifestMembershipChirho::NotInManifestChirho,
                terminal_disposition_chirho: Gd78TerminalDispositionChirho::CommittedFinalizeChirho,
                obligation_kind_chirho: Gd78ObligationKindChirho::CommittedOnLosingForkChirho,
                effect_lineage_chirho,
            });
        }
    }
}

impl Model for ModelGd78Chirho {
    type State = StateGd78Chirho;
    type Action = ActionGd78Chirho;

    fn init_states(&self) -> Vec<Self::State> {
        vec![StateGd78Chirho {
            phase_chirho: Gd78PhaseChirho::InitialChirho,
            manifest_membership_chirho: Gd78ManifestMembershipChirho::NotInManifestChirho,
            terminal_disposition_chirho: Gd78TerminalDispositionChirho::NoTerminalChirho,
            obligation_kind_chirho: Gd78ObligationKindChirho::NoObligationChirho,
            effect_lineage_chirho: Gd78EffectLineageChirho::ForwardChirho,
            obligation_origin_chirho: Gd78ObligationOriginChirho::NoneChirho,
            obligation_identity_chirho: None,
            winner_signature_term_chirho: None,
            barrier_chirho: Gd78BarrierChirho::LiveChirho,
            current_winner_term_chirho: WINNER_TERM_CHIRHO,
            sink_highest_accepted_winner_term_chirho: WINNER_TERM_CHIRHO,
            sink_restart_count_chirho: 0,
            provider_call_count_chirho: 0,
            journal_append_count_chirho: 0,
            outcome_chirho: Gd78OutcomeChirho::PendingChirho,
        }]
    }

    fn actions(&self, state_chirho: &Self::State, actions_chirho: &mut Vec<Self::Action>) {
        match state_chirho.phase_chirho {
            Gd78PhaseChirho::InitialChirho => Self::seal_actions_chirho(actions_chirho),
            Gd78PhaseChirho::CaseSealedChirho => {
                let has_obligation_chirho = state_chirho.obligation_kind_chirho
                    != Gd78ObligationKindChirho::NoObligationChirho;
                if has_obligation_chirho {
                    if state_chirho.manifest_membership_chirho
                        == Gd78ManifestMembershipChirho::InManifestChirho
                        || !self.manifest_membership_law_chirho
                    {
                        actions_chirho.push(ActionGd78Chirho::MintBoundObligationChirho);
                    }
                    actions_chirho.push(ActionGd78Chirho::ConstructObligationChirho);
                    actions_chirho.push(ActionGd78Chirho::DeserializeObligationChirho);
                    actions_chirho.push(ActionGd78Chirho::ReplayForeignObligationChirho);
                }
                if state_chirho.terminal_disposition_chirho
                    == Gd78TerminalDispositionChirho::DefiniteNoEffectReleaseChirho
                {
                    actions_chirho.push(ActionGd78Chirho::ApplyDefiniteNoEffectReleaseChirho);
                }
            }
            Gd78PhaseChirho::ObligationReadyChirho => {
                actions_chirho.push(ActionGd78Chirho::SignWithCurrentWinnerChirho);
            }
            Gd78PhaseChirho::WinnerSignedChirho => {
                if state_chirho.barrier_chirho == Gd78BarrierChirho::LiveChirho {
                    actions_chirho.push(ActionGd78Chirho::RevokeBarrierChirho);
                }
                if state_chirho.sink_restart_count_chirho == 0 {
                    actions_chirho.push(ActionGd78Chirho::RestartSinkChirho);
                }
                actions_chirho.push(ActionGd78Chirho::AppendAtSinkChirho);
            }
            Gd78PhaseChirho::FinishedChirho => {}
        }
    }

    fn next_state(
        &self,
        last_chirho: &Self::State,
        action_chirho: Self::Action,
    ) -> Option<Self::State> {
        let mut next_chirho = last_chirho.clone();
        match action_chirho {
            ActionGd78Chirho::SealCaseChirho {
                manifest_membership_chirho,
                terminal_disposition_chirho,
                obligation_kind_chirho,
                effect_lineage_chirho,
            } => {
                if last_chirho.phase_chirho != Gd78PhaseChirho::InitialChirho {
                    return None;
                }
                next_chirho.phase_chirho = Gd78PhaseChirho::CaseSealedChirho;
                next_chirho.manifest_membership_chirho = manifest_membership_chirho;
                next_chirho.terminal_disposition_chirho = terminal_disposition_chirho;
                next_chirho.obligation_kind_chirho = obligation_kind_chirho;
                next_chirho.effect_lineage_chirho = effect_lineage_chirho;
            }
            ActionGd78Chirho::MintBoundObligationChirho => {
                if last_chirho.phase_chirho != Gd78PhaseChirho::CaseSealedChirho
                    || last_chirho.obligation_kind_chirho
                        == Gd78ObligationKindChirho::NoObligationChirho
                    || (last_chirho.manifest_membership_chirho
                        != Gd78ManifestMembershipChirho::InManifestChirho
                        && self.manifest_membership_law_chirho)
                {
                    return None;
                }
                next_chirho.phase_chirho = Gd78PhaseChirho::ObligationReadyChirho;
                next_chirho.obligation_origin_chirho =
                    Gd78ObligationOriginChirho::SealedPlanMintChirho;
                next_chirho.obligation_identity_chirho =
                    Some(self.mutate_identity_chirho(Self::expected_identity_chirho(last_chirho)));
            }
            ActionGd78Chirho::ConstructObligationChirho
            | ActionGd78Chirho::DeserializeObligationChirho
            | ActionGd78Chirho::ReplayForeignObligationChirho => {
                if last_chirho.phase_chirho != Gd78PhaseChirho::CaseSealedChirho
                    || last_chirho.obligation_kind_chirho
                        == Gd78ObligationKindChirho::NoObligationChirho
                {
                    return None;
                }
                next_chirho.phase_chirho = Gd78PhaseChirho::ObligationReadyChirho;
                next_chirho.obligation_origin_chirho = match action_chirho {
                    ActionGd78Chirho::ConstructObligationChirho => {
                        Gd78ObligationOriginChirho::ConstructedChirho
                    }
                    ActionGd78Chirho::DeserializeObligationChirho => {
                        Gd78ObligationOriginChirho::DeserializedChirho
                    }
                    ActionGd78Chirho::ReplayForeignObligationChirho => {
                        Gd78ObligationOriginChirho::ForeignReconciliationChirho
                    }
                    _ => unreachable!(),
                };
                next_chirho.obligation_identity_chirho =
                    Some(Self::expected_identity_chirho(last_chirho));
            }
            ActionGd78Chirho::SignWithCurrentWinnerChirho => {
                if last_chirho.phase_chirho != Gd78PhaseChirho::ObligationReadyChirho {
                    return None;
                }
                next_chirho.phase_chirho = Gd78PhaseChirho::WinnerSignedChirho;
                next_chirho.winner_signature_term_chirho =
                    Some(last_chirho.current_winner_term_chirho);
            }
            ActionGd78Chirho::RevokeBarrierChirho => {
                if last_chirho.phase_chirho != Gd78PhaseChirho::WinnerSignedChirho
                    || last_chirho.barrier_chirho != Gd78BarrierChirho::LiveChirho
                {
                    return None;
                }
                next_chirho.barrier_chirho = Gd78BarrierChirho::RevokedChirho;
                next_chirho.current_winner_term_chirho = GD78_REVOKED_WINNER_TERM_CHIRHO;
                next_chirho.sink_highest_accepted_winner_term_chirho =
                    GD78_REVOKED_WINNER_TERM_CHIRHO;
            }
            ActionGd78Chirho::RestartSinkChirho => {
                if last_chirho.phase_chirho != Gd78PhaseChirho::WinnerSignedChirho
                    || last_chirho.sink_restart_count_chirho != 0
                {
                    return None;
                }
                next_chirho.sink_restart_count_chirho = 1;
                if !self.sink_term_persistence_law_chirho {
                    next_chirho.sink_highest_accepted_winner_term_chirho =
                        last_chirho.winner_signature_term_chirho?;
                }
            }
            ActionGd78Chirho::AppendAtSinkChirho => {
                if last_chirho.phase_chirho != Gd78PhaseChirho::WinnerSignedChirho {
                    return None;
                }
                next_chirho.phase_chirho = Gd78PhaseChirho::FinishedChirho;
                let Some(identity_chirho) = last_chirho.obligation_identity_chirho else {
                    next_chirho.outcome_chirho = Gd78OutcomeChirho::RefusedProvenanceChirho;
                    return Some(next_chirho);
                };
                let membership_accepted_chirho = last_chirho.manifest_membership_chirho
                    == Gd78ManifestMembershipChirho::InManifestChirho
                    || !self.manifest_membership_law_chirho;
                let provenance_accepted_chirho = membership_accepted_chirho
                    && self.origin_is_accepted_chirho(last_chirho.obligation_origin_chirho)
                    && self.identity_is_accepted_chirho(last_chirho, identity_chirho);
                if !provenance_accepted_chirho {
                    next_chirho.outcome_chirho = Gd78OutcomeChirho::RefusedProvenanceChirho;
                    return Some(next_chirho);
                }
                // This is the modeled sink-side append boundary. The persistent highest term and
                // supplied signed term are compared before either externally visible counter can
                // move. No in-process barrier borrow participates in this cross-process decision.
                let sink_fence_accepted_chirho = !self.sink_term_fence_law_chirho
                    || last_chirho.winner_signature_term_chirho
                        == Some(last_chirho.sink_highest_accepted_winner_term_chirho);
                if !sink_fence_accepted_chirho {
                    next_chirho.outcome_chirho = Gd78OutcomeChirho::RefusedSinkFenceChirho;
                    return Some(next_chirho);
                }
                if last_chirho.effect_lineage_chirho
                    == Gd78EffectLineageChirho::CompensationOfCompensationChirho
                    && !self.compensation_lineage_law_chirho
                {
                    next_chirho.outcome_chirho = Gd78OutcomeChirho::SilentlySkippedLineageChirho;
                    return Some(next_chirho);
                }
                match last_chirho.obligation_kind_chirho {
                    Gd78ObligationKindChirho::CommittedOnLosingForkChirho => {
                        next_chirho.provider_call_count_chirho = 1;
                        next_chirho.journal_append_count_chirho = 1;
                        next_chirho.outcome_chirho = Gd78OutcomeChirho::ConsumedCompensationChirho;
                    }
                    Gd78ObligationKindChirho::InDoubtHoldOnLosingForkChirho => {
                        next_chirho.journal_append_count_chirho = 1;
                        next_chirho.outcome_chirho = Gd78OutcomeChirho::HeldInDoubtChirho;
                    }
                    Gd78ObligationKindChirho::NoObligationChirho => {
                        next_chirho.outcome_chirho = Gd78OutcomeChirho::RefusedProvenanceChirho;
                    }
                }
            }
            ActionGd78Chirho::ApplyDefiniteNoEffectReleaseChirho => {
                if last_chirho.phase_chirho != Gd78PhaseChirho::CaseSealedChirho
                    || last_chirho.terminal_disposition_chirho
                        != Gd78TerminalDispositionChirho::DefiniteNoEffectReleaseChirho
                {
                    return None;
                }
                next_chirho.phase_chirho = Gd78PhaseChirho::FinishedChirho;
                next_chirho.outcome_chirho = if self.definite_release_law_chirho {
                    Gd78OutcomeChirho::DefiniteNoEffectReleasedChirho
                } else {
                    Gd78OutcomeChirho::IncorrectlyHeldDefiniteReleaseChirho
                };
            }
        }
        Some(next_chirho)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::<Self>::always(
                "gd7-8-manifest-membership-bound-chirho",
                |_, state_chirho| {
                    !Self::side_effected_chirho(state_chirho)
                        || state_chirho.manifest_membership_chirho
                            == Gd78ManifestMembershipChirho::InManifestChirho
                },
            ),
            Property::<Self>::always(
                "gd7-8-sealed-plan-identity-bound-chirho",
                |_, state_chirho| {
                    Self::binding_property_chirho(
                        state_chirho,
                        Gd78IdentityCoordinateChirho::SealedPlanIdentityChirho,
                    )
                },
            ),
            Property::<Self>::always(
                "gd7-8-winner-reconciliation-term-bound-chirho",
                |_, state_chirho| {
                    Self::binding_property_chirho(
                        state_chirho,
                        Gd78IdentityCoordinateChirho::WinnerReconciliationTermChirho,
                    )
                },
            ),
            Property::<Self>::always("gd7-8-obligation-kind-bound-chirho", |_, state_chirho| {
                Self::binding_property_chirho(
                    state_chirho,
                    Gd78IdentityCoordinateChirho::ObligationKindChirho,
                )
            }),
            Property::<Self>::always("gd7-8-effect-lineage-bound-chirho", |_, state_chirho| {
                Self::binding_property_chirho(
                    state_chirho,
                    Gd78IdentityCoordinateChirho::EffectLineageChirho,
                )
            }),
            Property::<Self>::always(
                "gd7-8-original-effect-key-bound-chirho",
                |_, state_chirho| {
                    Self::binding_property_chirho(
                        state_chirho,
                        Gd78IdentityCoordinateChirho::OriginalEffectKeyChirho,
                    )
                },
            ),
            Property::<Self>::always(
                "gd7-8-terminal-disposition-bound-chirho",
                |_, state_chirho| {
                    Self::binding_property_chirho(
                        state_chirho,
                        Gd78IdentityCoordinateChirho::TerminalDispositionChirho,
                    )
                },
            ),
            Property::<Self>::always("gd7-8-terminal-marker-bound-chirho", |_, state_chirho| {
                Self::binding_property_chirho(
                    state_chirho,
                    Gd78IdentityCoordinateChirho::TerminalMarkerChirho,
                )
            }),
            Property::<Self>::always("gd7-8-source-seq-bound-chirho", |_, state_chirho| {
                Self::binding_property_chirho(
                    state_chirho,
                    Gd78IdentityCoordinateChirho::SourceSeqChirho,
                )
            }),
            Property::<Self>::always(
                "gd7-8-source-record-digest-bound-chirho",
                |_, state_chirho| {
                    Self::binding_property_chirho(
                        state_chirho,
                        Gd78IdentityCoordinateChirho::SourceRecordDigestChirho,
                    )
                },
            ),
            Property::<Self>::always(
                "gd7-8-constructed-obligation-refused-chirho",
                |_, state_chirho| {
                    !Self::side_effected_chirho(state_chirho)
                        || state_chirho.obligation_origin_chirho
                            != Gd78ObligationOriginChirho::ConstructedChirho
                },
            ),
            Property::<Self>::always(
                "gd7-8-deserialized-obligation-refused-chirho",
                |_, state_chirho| {
                    !Self::side_effected_chirho(state_chirho)
                        || state_chirho.obligation_origin_chirho
                            != Gd78ObligationOriginChirho::DeserializedChirho
                },
            ),
            Property::<Self>::always(
                "gd7-8-foreign-obligation-refused-after-current-signature-chirho",
                |_, state_chirho| {
                    !Self::side_effected_chirho(state_chirho)
                        || state_chirho.obligation_origin_chirho
                            != Gd78ObligationOriginChirho::ForeignReconciliationChirho
                },
            ),
            Property::<Self>::always(
                "gd7-8-revoked-barrier-zero-side-effects-chirho",
                |_, state_chirho| {
                    state_chirho.barrier_chirho != Gd78BarrierChirho::RevokedChirho
                        || (!Self::side_effected_chirho(state_chirho)
                            && state_chirho.sink_highest_accepted_winner_term_chirho
                                == GD78_REVOKED_WINNER_TERM_CHIRHO)
                },
            ),
            Property::<Self>::always(
                "gd7-8-sink-highest-term-survives-restart-chirho",
                |_, state_chirho| {
                    state_chirho.barrier_chirho != Gd78BarrierChirho::RevokedChirho
                        || state_chirho.sink_restart_count_chirho == 0
                        || state_chirho.sink_highest_accepted_winner_term_chirho
                            == GD78_REVOKED_WINNER_TERM_CHIRHO
                },
            ),
            Property::<Self>::always(
                "gd7-8-compensation-of-compensation-not-skipped-chirho",
                |_, state_chirho| {
                    state_chirho.outcome_chirho != Gd78OutcomeChirho::SilentlySkippedLineageChirho
                },
            ),
            Property::<Self>::always(
                "gd7-8-definite-no-effect-release-is-not-a-hold-chirho",
                |_, state_chirho| {
                    state_chirho.outcome_chirho
                        != Gd78OutcomeChirho::IncorrectlyHeldDefiniteReleaseChirho
                },
            ),
            Property::<Self>::sometimes(
                "gd7-8-forward-compensation-consumed-reachable-chirho",
                |_, state_chirho| {
                    state_chirho.effect_lineage_chirho == Gd78EffectLineageChirho::ForwardChirho
                        && state_chirho.outcome_chirho
                            == Gd78OutcomeChirho::ConsumedCompensationChirho
                        && state_chirho.provider_call_count_chirho == 1
                        && state_chirho.journal_append_count_chirho == 1
                },
            ),
            Property::<Self>::sometimes(
                "gd7-8-compensation-of-compensation-consumed-reachable-chirho",
                |_, state_chirho| {
                    state_chirho.effect_lineage_chirho
                        == Gd78EffectLineageChirho::CompensationOfCompensationChirho
                        && state_chirho.outcome_chirho
                            == Gd78OutcomeChirho::ConsumedCompensationChirho
                        && state_chirho.provider_call_count_chirho == 1
                        && state_chirho.journal_append_count_chirho == 1
                },
            ),
            Property::<Self>::sometimes(
                "gd7-8-in-doubt-obligation-handled-reachable-chirho",
                |_, state_chirho| {
                    state_chirho.obligation_kind_chirho
                        == Gd78ObligationKindChirho::InDoubtHoldOnLosingForkChirho
                        && state_chirho.outcome_chirho == Gd78OutcomeChirho::HeldInDoubtChirho
                        && state_chirho.provider_call_count_chirho == 0
                        && state_chirho.journal_append_count_chirho == 1
                },
            ),
            Property::<Self>::sometimes(
                "gd7-8-definite-no-effect-release-reachable-chirho",
                |_, state_chirho| {
                    state_chirho.terminal_disposition_chirho
                        == Gd78TerminalDispositionChirho::DefiniteNoEffectReleaseChirho
                        && state_chirho.outcome_chirho
                            == Gd78OutcomeChirho::DefiniteNoEffectReleasedChirho
                        && !Self::side_effected_chirho(state_chirho)
                },
            ),
            Property::<Self>::sometimes(
                "gd7-8-revoked-consumption-refused-reachable-chirho",
                |_, state_chirho| {
                    state_chirho.barrier_chirho == Gd78BarrierChirho::RevokedChirho
                        && state_chirho.outcome_chirho == Gd78OutcomeChirho::RefusedSinkFenceChirho
                        && !Self::side_effected_chirho(state_chirho)
                },
            ),
            Property::<Self>::sometimes(
                "gd7-8-restarted-sink-retains-revocation-reachable-chirho",
                |_, state_chirho| {
                    state_chirho.barrier_chirho == Gd78BarrierChirho::RevokedChirho
                        && state_chirho.sink_restart_count_chirho == 1
                        && state_chirho.outcome_chirho == Gd78OutcomeChirho::RefusedSinkFenceChirho
                        && !Self::side_effected_chirho(state_chirho)
                },
            ),
            Property::<Self>::sometimes(
                "gd7-8-constructed-current-signed-refusal-reachable-chirho",
                |_, state_chirho| {
                    state_chirho.obligation_origin_chirho
                        == Gd78ObligationOriginChirho::ConstructedChirho
                        && state_chirho.winner_signature_term_chirho == Some(WINNER_TERM_CHIRHO)
                        && state_chirho.outcome_chirho == Gd78OutcomeChirho::RefusedProvenanceChirho
                },
            ),
            Property::<Self>::sometimes(
                "gd7-8-deserialized-current-signed-refusal-reachable-chirho",
                |_, state_chirho| {
                    state_chirho.obligation_origin_chirho
                        == Gd78ObligationOriginChirho::DeserializedChirho
                        && state_chirho.winner_signature_term_chirho == Some(WINNER_TERM_CHIRHO)
                        && state_chirho.outcome_chirho == Gd78OutcomeChirho::RefusedProvenanceChirho
                },
            ),
            Property::<Self>::sometimes(
                "gd7-8-foreign-current-signed-refusal-reachable-chirho",
                |_, state_chirho| {
                    state_chirho.obligation_origin_chirho
                        == Gd78ObligationOriginChirho::ForeignReconciliationChirho
                        && state_chirho.winner_signature_term_chirho == Some(WINNER_TERM_CHIRHO)
                        && state_chirho.outcome_chirho == Gd78OutcomeChirho::RefusedProvenanceChirho
                },
            ),
            Property::<Self>::sometimes(
                "gd7-8-not-in-manifest-refusal-reachable-chirho",
                |_, state_chirho| {
                    state_chirho.manifest_membership_chirho
                        == Gd78ManifestMembershipChirho::NotInManifestChirho
                        && state_chirho.outcome_chirho == Gd78OutcomeChirho::RefusedProvenanceChirho
                },
            ),
        ]
    }
}

#[cfg(test)]
#[path = "model_gd7_reconciliation_tests_chirho.rs"]
mod tests_chirho;
