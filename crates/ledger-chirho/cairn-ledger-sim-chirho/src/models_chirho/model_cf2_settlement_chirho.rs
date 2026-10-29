// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! CF2 F3 keystone — cross-cluster consume-once + settlement conservation, model-checked with
//! stateright and PROVEN load-bearing by a buggy-mode twin (the mutation-rigor teeth).
//!
//! Frozen §11.8 (F3): a cross-cluster transfer A(cluster 1) → B(cluster 2) is settlement-STATE over
//! saga-CONTROL. The value crosses via a source BURN in cluster 1 (`A → settlement₁`, a balanced
//! cluster-1 record) that mints a consume-once NULLIFIER, then a destination CREDIT in cluster 2
//! (`settlement₂ → B`, a balanced cluster-2 record) gated on the burn being FINAL and the nullifier
//! UNCONSUMED. The hazard the whole F3 design exists to kill: ONE burn justifying N credits (a
//! counterpart hash alone is replayable). The consumed-nullifier set is the guard.
//!
//! The safety expressed as a CONSERVATION equation: `settlement₁.credits == settlement₂.debits` —
//! every burn that funds settlement₁ matches exactly one credit drained from settlement₂. A
//! double-consume drains settlement₂ twice for one burn → the bilateral position breaks (S₂ drains
//! faster than S₁ funds → the net-settlement ceremony cannot reconcile). This is the F3
//! bilateral-position monitor as a checked invariant.
//!
//! Properties (over every interleaving of one burn + two concurrent destination claims on it):
//! - **F3-bilateral (always, enforced)** — `S₂.debits ≤ S₁.credits`: settlement₂ never drains more
//!   than settlement₁ was funded, so a burn is claimed at most once (mid-flight the burn funds S₁
//!   before the claim drains S₂; a double-consume would break `≤`).
//! - **global-conservation (always)** — `Σ(credits − debits)` over all accounts is invariant.
//! - **no-overdraft (always)** — every account (incl. settlements) spendable ≥ 0.
//! - **finality (structural)** — a claim requires the burn recorded first (a credit against a
//!   non-final burn is not a reachable transition).
//! - **live (sometimes)** — the burn is claimed (the fences are not vacuously safe).
//!
//! MUTATION-RIGOR TWIN: a `buggy` mode drops the consumed-nullifier check; the twin proves a
//! double-consume (`S₂.debits > S₁.credits`) is then REACHABLE — so the consumed-set check is
//! load-bearing, and F3-bilateral is non-vacuous.

use stateright::{Model, Property};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AcctChirho {
    pub credits_chirho: u64,
    pub debits_chirho: u64,
}

impl AcctChirho {
    fn spendable_chirho(&self) -> i128 {
        i128::from(self.credits_chirho) - i128::from(self.debits_chirho)
    }
}

// Account indices: 0 = A (cluster-1 source), 1 = S₁ (cluster-1 settlement), 2 = S₂ (cluster-2
// settlement), 3 = B₁, 4 = B₂ (cluster-2 destinations).
const A_CHIRHO: usize = 0;
const S1_CHIRHO: usize = 1;
const S2_CHIRHO: usize = 2;
const AMOUNT_CHIRHO: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StateSettlementChirho {
    pub accounts_chirho: Vec<AcctChirho>,
    pub burn_recorded_chirho: bool,
    pub nullifier_consumed_chirho: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ActionSettlementChirho {
    BurnChirho,
    ClaimChirho { destination_chirho: usize },
}

/// Model config. `enforce_consume_once` toggles the consumed-nullifier guard: `true` is the real
/// protocol, `false` is the mutation twin that proves the guard load-bearing.
pub struct ModelCf2SettlementChirho {
    pub enforce_consume_once_chirho: bool,
}

impl ModelCf2SettlementChirho {
    fn initial_accounts_chirho() -> Vec<AcctChirho> {
        vec![
            AcctChirho {
                credits_chirho: AMOUNT_CHIRHO,
                debits_chirho: 0,
            }, // A funded for one burn
            AcctChirho {
                credits_chirho: 0,
                debits_chirho: 0,
            }, // S₁
            AcctChirho {
                credits_chirho: 10,
                debits_chirho: 0,
            }, // S₂ pre-funded (funding law)
            AcctChirho {
                credits_chirho: 0,
                debits_chirho: 0,
            }, // B₁
            AcctChirho {
                credits_chirho: 0,
                debits_chirho: 0,
            }, // B₂
        ]
    }

    fn initial_total_chirho() -> i128 {
        Self::initial_accounts_chirho()
            .iter()
            .map(AcctChirho::spendable_chirho)
            .sum()
    }
}

impl Model for ModelCf2SettlementChirho {
    type State = StateSettlementChirho;
    type Action = ActionSettlementChirho;

    fn init_states(&self) -> Vec<Self::State> {
        vec![StateSettlementChirho {
            accounts_chirho: Self::initial_accounts_chirho(),
            burn_recorded_chirho: false,
            nullifier_consumed_chirho: false,
        }]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        // The source burn: A → settlement₁ (once, if A can afford it).
        if !state.burn_recorded_chirho
            && state.accounts_chirho[A_CHIRHO].spendable_chirho() >= i128::from(AMOUNT_CHIRHO)
        {
            actions.push(ActionSettlementChirho::BurnChirho);
        }
        // Destination claims on the burn's nullifier — offered to BOTH B₁ and B₂ (the replay
        // attack). Finality is structural: the burn must be recorded first. The consumed guard is
        // applied only when enforced.
        if state.burn_recorded_chirho
            && (!self.enforce_consume_once_chirho || !state.nullifier_consumed_chirho)
            && state.accounts_chirho[S2_CHIRHO].spendable_chirho() >= i128::from(AMOUNT_CHIRHO)
        {
            for destination_chirho in [3usize, 4usize] {
                actions.push(ActionSettlementChirho::ClaimChirho { destination_chirho });
            }
        }
    }

    fn next_state(&self, state: &Self::State, action: Self::Action) -> Option<Self::State> {
        let mut next_chirho = state.clone();
        match action {
            ActionSettlementChirho::BurnChirho => {
                next_chirho.accounts_chirho[A_CHIRHO].debits_chirho += AMOUNT_CHIRHO;
                next_chirho.accounts_chirho[S1_CHIRHO].credits_chirho += AMOUNT_CHIRHO;
                next_chirho.burn_recorded_chirho = true;
            }
            ActionSettlementChirho::ClaimChirho { destination_chirho } => {
                next_chirho.accounts_chirho[S2_CHIRHO].debits_chirho += AMOUNT_CHIRHO;
                next_chirho.accounts_chirho[destination_chirho].credits_chirho += AMOUNT_CHIRHO;
                next_chirho.nullifier_consumed_chirho = true;
            }
        }
        Some(next_chirho)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        let mut properties_chirho = vec![
            Property::<Self>::always("global-conservation-chirho", |_, state| {
                state
                    .accounts_chirho
                    .iter()
                    .map(AcctChirho::spendable_chirho)
                    .sum::<i128>()
                    == ModelCf2SettlementChirho::initial_total_chirho()
            }),
            Property::<Self>::always("no-overdraft-chirho", |_, state| {
                state
                    .accounts_chirho
                    .iter()
                    .all(|acct_chirho| acct_chirho.spendable_chirho() >= 0)
            }),
            Property::<Self>::sometimes("live-burn-claimed-chirho", |_, state| {
                state.nullifier_consumed_chirho
            }),
        ];
        if self.enforce_consume_once_chirho {
            // F3 bilateral position (consume-once): settlement₂ never drains MORE than settlement₁
            // was funded — you cannot claim a burn more times than it was burned. Mid-flight the
            // burn funds S₁ before the claim drains S₂ (`0 ≤ 1`); a double-consume would give
            // `S₂.debits > S₁.credits`, which this forbids in every reachable state.
            properties_chirho.push(Property::<Self>::always(
                "f3-bilateral-consume-once-chirho",
                |_, state| {
                    state.accounts_chirho[S2_CHIRHO].debits_chirho
                        <= state.accounts_chirho[S1_CHIRHO].credits_chirho
                },
            ));
        } else {
            // The mutation twin: WITHOUT the consumed guard, a double-consume (S₂ drained twice for
            // one burn) is REACHABLE — proving the guard is load-bearing and F3-bilateral non-vacuous.
            properties_chirho.push(Property::<Self>::sometimes(
                "double-consume-reachable-without-guard-chirho",
                |_, state| {
                    state.accounts_chirho[S2_CHIRHO].debits_chirho
                        > state.accounts_chirho[S1_CHIRHO].credits_chirho
                },
            ));
        }
        properties_chirho
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use stateright::Checker;

    #[test]
    fn cf2_f3_consume_once_holds_under_concurrent_claims_chirho() {
        // The real protocol: one burn, two concurrent claims on its nullifier. Consume-once
        // (S₁.credits == S₂.debits), conservation, and no-overdraft hold across EVERY interleaving;
        // the burn is claimable (non-vacuous).
        ModelCf2SettlementChirho {
            enforce_consume_once_chirho: true,
        }
        .checker()
        .spawn_bfs()
        .join()
        .assert_properties();
    }

    #[test]
    fn cf2_consumed_guard_is_load_bearing_chirho() {
        // The mutation twin: drop the consumed-nullifier guard and the model checker FINDS a
        // double-consume (S₂ drained twice for one burn) — so the guard is what makes consume-once
        // hold, and the F3-bilateral invariant above is non-vacuous. (assert_properties passes iff
        // the `sometimes double-consume-reachable` witness is found.)
        ModelCf2SettlementChirho {
            enforce_consume_once_chirho: false,
        }
        .checker()
        .spawn_bfs()
        .join()
        .assert_properties();
    }
}
