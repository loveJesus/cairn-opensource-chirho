// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! CF2 keystone — the escrow two-phase transfer lifecycle, exhaustively model-checked with
//! stateright BEFORE the CF2 build (the abstract de-risk, like Model C for the CF1 packing).
//!
//! Grounded in the frozen §12 saga skeleton: a transfer moves value from `from` to `to` through a
//! settlement account `S` that carries the in-flight value (settlement-STATE over saga-CONTROL).
//! The lifecycle is `Init → Held → Credited → (Finalized | Released | Compensated)`:
//! - **Hold** — `from.held += amount` (requires `from` spendable ≥ amount; the §11.3 fence).
//! - **Credit** — `S.debits += amount, to.credits += amount` (B credited FROM settlement; requires
//!   `S` pre-funded, the F3 funding law). `Held → Credited`.
//! - **Finalize** — `from.held -= amount, from.debits += amount, S.credits += amount` (the hold
//!   becomes a real debit, settlement refilled). `Credited → Finalized`.
//! - **Release** (abort) — `from.held -= amount`. Legal ONLY from `Held` (T1: no credit happened).
//! - **Compensate** (abort) — `from.held -= amount, to.debits += amount, S.credits += amount`
//!   (reverse the credit post-facto). Legal ONLY from `Credited` (T1: after credit, never a
//!   unilateral release — compensate-the-credit).
//!
//! Properties checked across every interleaving of two concurrent transfers sharing accounts:
//! - **C1 conservation (always)** — `Σ(credits − debits)` over all accounts is INVARIANT (every
//!   step is balanced; the in-flight value lives in `held`, not in a created/destroyed balance).
//! - **C2 no-overdraft (always)** — every account's spendable `credits − debits − held ≥ 0`.
//! - **C3 held-matches-in-flight (always)** — total `held == Σ amount` over transfers currently in
//!   `Held`/`Credited` (no lost hold, no phantom hold).
//! - **C4 debits-match-phases-exactly (always)** — every account's debits equal EXACTLY its
//!   phase-implied debit sum across the three sources (settlement-on-credit, from-on-finalize,
//!   to-on-compensate), pinning no-double-debit: each source fires at most once per transfer.
//! - **T1 (structural)** — `Release` only from `Held`, `Compensate` only from `Credited`; enforced
//!   by `actions`, so an illegal abort is simply not a reachable transition.
//! - **L-live (sometimes)** — all transfers reach a terminal phase (the protocol is not wedged).
//!
//! Cross-cluster settlement (two settlement accounts `S₁`/`S₂`, the nullifier consume-once, the
//! net-settlement ceremony) composes ON this lifecycle at CF2 build time; this model proves the
//! single-settlement escrow core the whole protocol rests on.

use stateright::{Model, Property};

/// An account's running totals (the §11.2 shape, abstracted to unit-scale).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AcctChirho {
    pub credits_chirho: u64,
    pub debits_chirho: u64,
    pub held_chirho: u64,
}

impl AcctChirho {
    fn spendable_chirho(&self) -> i128 {
        i128::from(self.credits_chirho)
            - i128::from(self.debits_chirho)
            - i128::from(self.held_chirho)
    }
    fn balance_chirho(&self) -> i128 {
        i128::from(self.credits_chirho) - i128::from(self.debits_chirho)
    }
}

/// The saga phase of one transfer (frozen §12 lifecycle).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PhaseChirho {
    InitChirho,
    HeldChirho,
    CreditedChirho,
    FinalizedChirho,
    ReleasedChirho,
    CompensatedChirho,
}

impl PhaseChirho {
    fn is_terminal_chirho(self) -> bool {
        matches!(
            self,
            PhaseChirho::FinalizedChirho
                | PhaseChirho::ReleasedChirho
                | PhaseChirho::CompensatedChirho
        )
    }
}

/// One transfer's static spec: move `amount` from account `from` to account `to`, in-flight via `S`.
#[derive(Clone, Copy, Debug)]
pub struct TransferSpecChirho {
    pub from_chirho: usize,
    pub to_chirho: usize,
    pub amount_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StateCf2Chirho {
    pub accounts_chirho: Vec<AcctChirho>,
    pub phases_chirho: Vec<PhaseChirho>,
}

/// A transition: advance transfer `i` by its next legal saga step. The abort steps (`Release`,
/// `Compensate`) are OFFERED as alternatives to the forward step, so stateright explores commit AND
/// both abort paths under every interleaving.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ActionCf2Chirho {
    HoldChirho { transfer_chirho: usize },
    CreditChirho { transfer_chirho: usize },
    FinalizeChirho { transfer_chirho: usize },
    ReleaseChirho { transfer_chirho: usize },
    CompensateChirho { transfer_chirho: usize },
}

/// Model config — a fixed set of accounts (one is the settlement account) + transfer specs.
pub struct ModelCf2Chirho {
    pub initial_accounts_chirho: Vec<AcctChirho>,
    pub settlement_chirho: usize,
    pub transfers_chirho: Vec<TransferSpecChirho>,
}

impl ModelCf2Chirho {
    fn initial_total_chirho(&self) -> i128 {
        self.initial_accounts_chirho
            .iter()
            .map(AcctChirho::balance_chirho)
            .sum()
    }
}

impl Model for ModelCf2Chirho {
    type State = StateCf2Chirho;
    type Action = ActionCf2Chirho;

    fn init_states(&self) -> Vec<Self::State> {
        vec![StateCf2Chirho {
            accounts_chirho: self.initial_accounts_chirho.clone(),
            phases_chirho: vec![PhaseChirho::InitChirho; self.transfers_chirho.len()],
        }]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        for (index_chirho, spec_chirho) in self.transfers_chirho.iter().enumerate() {
            match state.phases_chirho[index_chirho] {
                PhaseChirho::InitChirho => {
                    // Hold is offered only if `from` can afford it (the spendable fence).
                    if state.accounts_chirho[spec_chirho.from_chirho].spendable_chirho()
                        >= i128::from(spec_chirho.amount_chirho)
                    {
                        actions.push(ActionCf2Chirho::HoldChirho {
                            transfer_chirho: index_chirho,
                        });
                    }
                }
                PhaseChirho::HeldChirho => {
                    // Forward: credit `to` from settlement (only if settlement is funded).
                    if state.accounts_chirho[self.settlement_chirho].spendable_chirho()
                        >= i128::from(spec_chirho.amount_chirho)
                    {
                        actions.push(ActionCf2Chirho::CreditChirho {
                            transfer_chirho: index_chirho,
                        });
                    }
                    // Abort (T1: legal because no credit yet).
                    actions.push(ActionCf2Chirho::ReleaseChirho {
                        transfer_chirho: index_chirho,
                    });
                }
                PhaseChirho::CreditedChirho => {
                    actions.push(ActionCf2Chirho::FinalizeChirho {
                        transfer_chirho: index_chirho,
                    });
                    // Abort (T1: after credit, compensate — never a unilateral release).
                    actions.push(ActionCf2Chirho::CompensateChirho {
                        transfer_chirho: index_chirho,
                    });
                }
                PhaseChirho::FinalizedChirho
                | PhaseChirho::ReleasedChirho
                | PhaseChirho::CompensatedChirho => {}
            }
        }
    }

    fn next_state(&self, state: &Self::State, action: Self::Action) -> Option<Self::State> {
        let mut next_chirho = state.clone();
        match action {
            ActionCf2Chirho::HoldChirho { transfer_chirho } => {
                let spec_chirho = &self.transfers_chirho[transfer_chirho];
                next_chirho.accounts_chirho[spec_chirho.from_chirho].held_chirho +=
                    spec_chirho.amount_chirho;
                next_chirho.phases_chirho[transfer_chirho] = PhaseChirho::HeldChirho;
            }
            ActionCf2Chirho::CreditChirho { transfer_chirho } => {
                let spec_chirho = &self.transfers_chirho[transfer_chirho];
                next_chirho.accounts_chirho[self.settlement_chirho].debits_chirho +=
                    spec_chirho.amount_chirho;
                next_chirho.accounts_chirho[spec_chirho.to_chirho].credits_chirho +=
                    spec_chirho.amount_chirho;
                next_chirho.phases_chirho[transfer_chirho] = PhaseChirho::CreditedChirho;
            }
            ActionCf2Chirho::FinalizeChirho { transfer_chirho } => {
                let spec_chirho = &self.transfers_chirho[transfer_chirho];
                next_chirho.accounts_chirho[spec_chirho.from_chirho].held_chirho -=
                    spec_chirho.amount_chirho;
                next_chirho.accounts_chirho[spec_chirho.from_chirho].debits_chirho +=
                    spec_chirho.amount_chirho;
                next_chirho.accounts_chirho[self.settlement_chirho].credits_chirho +=
                    spec_chirho.amount_chirho;
                next_chirho.phases_chirho[transfer_chirho] = PhaseChirho::FinalizedChirho;
            }
            ActionCf2Chirho::ReleaseChirho { transfer_chirho } => {
                let spec_chirho = &self.transfers_chirho[transfer_chirho];
                next_chirho.accounts_chirho[spec_chirho.from_chirho].held_chirho -=
                    spec_chirho.amount_chirho;
                next_chirho.phases_chirho[transfer_chirho] = PhaseChirho::ReleasedChirho;
            }
            ActionCf2Chirho::CompensateChirho { transfer_chirho } => {
                let spec_chirho = &self.transfers_chirho[transfer_chirho];
                // Reverse the credit (to gives back, settlement refilled) AND release from's hold.
                next_chirho.accounts_chirho[spec_chirho.to_chirho].debits_chirho +=
                    spec_chirho.amount_chirho;
                next_chirho.accounts_chirho[self.settlement_chirho].credits_chirho +=
                    spec_chirho.amount_chirho;
                next_chirho.accounts_chirho[spec_chirho.from_chirho].held_chirho -=
                    spec_chirho.amount_chirho;
                next_chirho.phases_chirho[transfer_chirho] = PhaseChirho::CompensatedChirho;
            }
        }
        Some(next_chirho)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::<Self>::always("c1-conservation-chirho", |model_chirho, state| {
                state
                    .accounts_chirho
                    .iter()
                    .map(AcctChirho::balance_chirho)
                    .sum::<i128>()
                    == model_chirho.initial_total_chirho()
            }),
            Property::<Self>::always("c2-no-overdraft-chirho", |_, state| {
                state
                    .accounts_chirho
                    .iter()
                    .all(|acct_chirho| acct_chirho.spendable_chirho() >= 0)
            }),
            Property::<Self>::always("c3-held-matches-in-flight-chirho", |model_chirho, state| {
                let held_total_chirho: u64 = state
                    .accounts_chirho
                    .iter()
                    .map(|acct_chirho| acct_chirho.held_chirho)
                    .sum();
                let in_flight_chirho: u64 = model_chirho
                    .transfers_chirho
                    .iter()
                    .enumerate()
                    .filter(|(index_chirho, _)| {
                        matches!(
                            state.phases_chirho[*index_chirho],
                            PhaseChirho::HeldChirho | PhaseChirho::CreditedChirho
                        )
                    })
                    .map(|(_, spec_chirho)| spec_chirho.amount_chirho)
                    .sum();
                held_total_chirho == in_flight_chirho
            }),
            Property::<Self>::always(
                "c4-debits-match-phases-exactly-chirho",
                |model_chirho, state| {
                    // Every account's debits equal EXACTLY the phase-implied sum of its three debit
                    // sources — pinning no-double-debit (each source fires at most once per transfer):
                    //  - the SETTLEMENT account is debited on CREDIT (crediting `to` from settlement) —
                    //    for every transfer that reached Credited-or-beyond;
                    //  - `from` is debited on FINALIZE only (never on release/compensate);
                    //  - `to` is debited on COMPENSATE only (reversing the credit).
                    (0..state.accounts_chirho.len()).all(|acct_chirho| {
                        let expected_chirho: u64 = model_chirho
                            .transfers_chirho
                            .iter()
                            .enumerate()
                            .map(|(index_chirho, spec_chirho)| {
                                let phase_chirho = state.phases_chirho[index_chirho];
                                let credited_chirho = matches!(
                                    phase_chirho,
                                    PhaseChirho::CreditedChirho
                                        | PhaseChirho::FinalizedChirho
                                        | PhaseChirho::CompensatedChirho
                                );
                                let mut owed_chirho = 0;
                                if acct_chirho == model_chirho.settlement_chirho && credited_chirho
                                {
                                    owed_chirho += spec_chirho.amount_chirho;
                                }
                                if spec_chirho.from_chirho == acct_chirho
                                    && phase_chirho == PhaseChirho::FinalizedChirho
                                {
                                    owed_chirho += spec_chirho.amount_chirho;
                                }
                                if spec_chirho.to_chirho == acct_chirho
                                    && phase_chirho == PhaseChirho::CompensatedChirho
                                {
                                    owed_chirho += spec_chirho.amount_chirho;
                                }
                                owed_chirho
                            })
                            .sum();
                        state.accounts_chirho[acct_chirho].debits_chirho == expected_chirho
                    })
                },
            ),
            Property::<Self>::sometimes("l-live-all-terminal-chirho", |_, state| {
                state
                    .phases_chirho
                    .iter()
                    .all(|phase_chirho| phase_chirho.is_terminal_chirho())
            }),
        ]
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use stateright::Checker;

    fn acct_chirho(credits_chirho: u64) -> AcctChirho {
        AcctChirho {
            credits_chirho,
            debits_chirho: 0,
            held_chirho: 0,
        }
    }

    #[test]
    fn cf2_escrow_transfer_lifecycle_holds_all_invariants_chirho() {
        // Accounts: 0=A (funded 2), 1=B, 2=C, 3=S (settlement, pre-funded 10). Two concurrent
        // transfers share the from-account A: A→B(1) and A→C(1). Every interleaving of hold/credit/
        // finalize/release/compensate across both transfers is explored exhaustively.
        let model_chirho = ModelCf2Chirho {
            initial_accounts_chirho: vec![
                acct_chirho(2),
                acct_chirho(0),
                acct_chirho(0),
                acct_chirho(10),
            ],
            settlement_chirho: 3,
            transfers_chirho: vec![
                TransferSpecChirho {
                    from_chirho: 0,
                    to_chirho: 1,
                    amount_chirho: 1,
                },
                TransferSpecChirho {
                    from_chirho: 0,
                    to_chirho: 2,
                    amount_chirho: 1,
                },
            ],
        };
        model_chirho
            .checker()
            .spawn_bfs()
            .join()
            .assert_properties();
    }

    #[test]
    fn cf2_overdraft_fence_holds_when_from_can_afford_only_one_chirho() {
        // A funded with only 1: the two transfers A→B(1) and A→C(1) CANNOT both hold at once. The
        // spendable fence in `actions` must keep no-overdraft across every interleaving (the second
        // hold is simply unavailable until the first finalizes/releases and frees the balance).
        let model_chirho = ModelCf2Chirho {
            initial_accounts_chirho: vec![
                acct_chirho(1),
                acct_chirho(0),
                acct_chirho(0),
                acct_chirho(10),
            ],
            settlement_chirho: 3,
            transfers_chirho: vec![
                TransferSpecChirho {
                    from_chirho: 0,
                    to_chirho: 1,
                    amount_chirho: 1,
                },
                TransferSpecChirho {
                    from_chirho: 0,
                    to_chirho: 2,
                    amount_chirho: 1,
                },
            ],
        };
        model_chirho
            .checker()
            .spawn_bfs()
            .join()
            .assert_properties();
    }

    #[test]
    fn cf2_settlement_funding_law_holds_when_settlement_is_thin_chirho() {
        // Settlement pre-funded with only 1: two transfers cannot both be Credited-out at once (the
        // F3 funding law — settlement must hold ≥ amount to credit `to`). Conservation + the funding
        // fence must hold across every interleaving.
        let model_chirho = ModelCf2Chirho {
            initial_accounts_chirho: vec![
                acct_chirho(2),
                acct_chirho(0),
                acct_chirho(0),
                acct_chirho(1),
            ],
            settlement_chirho: 3,
            transfers_chirho: vec![
                TransferSpecChirho {
                    from_chirho: 0,
                    to_chirho: 1,
                    amount_chirho: 1,
                },
                TransferSpecChirho {
                    from_chirho: 0,
                    to_chirho: 2,
                    amount_chirho: 1,
                },
            ],
        };
        model_chirho
            .checker()
            .spawn_bfs()
            .join()
            .assert_properties();
    }
}
