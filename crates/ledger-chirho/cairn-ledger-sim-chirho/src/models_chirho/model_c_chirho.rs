// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Model C — the hot-account sharded-credit escape, exhaustively model-checked with stateright.
//!
//! This is the make-or-break proof for the CF1 per-cluster-journal packing decision: a platform-fee
//! account is credited by every transfer, so a single account would serialize the whole cluster. The
//! escape is a fan-out into N credit-only sub-accounts (credits commute) plus one primary that
//! consolidation drains into and debits draw from. This module proves the escape rather than asserts
//! it, against the six acceptance criteria in cf2-transfer-model-comparison-chirho.md:
//!
//! - **C1 credits commute** — a credit to sub i and a credit to sub j (i != j) reach the same state in
//!   either order (a CRDT diamond); no ordering is ever forced between different sub-accounts.
//! - **C2 no cross-shard read on the credit path** — a credit to sub i touches ONLY sub i.
//! - **C3 debit folds conservatively** — a debit draws from the primary ONLY (never a cross-shard
//!   sum); an underfunded primary must be topped up by consolidation first; F4 (no over-debit) holds.
//! - **C4 conservation across the fan-out** — Σ(subs) + primary == total_credited − total_debited at
//!   every reachable state; sharding neither leaks nor creates value.
//! - **C5 the escape scales** — the credit path has no shared serialization point (follows from C1+C2),
//!   so concurrent-credit throughput grows with N. **C5-R1 (claude2 money-gate, the honest bound):
//!   COMMUTATIVITY != CONCURRENCY.** This model PROVES credits commute (order-insensitive RESULT) —
//!   necessary but NOT sufficient for "scales". `total_credited_chirho`/`total_debited_chirho` here are
//!   MODELING aggregates (they make C4 conservation checkable as a state property); they are NOT a
//!   runtime write-path counter. "Scales" holds ONLY IF the real impl keeps only PER-ACCOUNT post-state
//!   on the write path (each record carries its own account's running totals — no cross-account
//!   contention) and DERIVES the GLOBAL conservation aggregates at read time (Σ over per-account
//!   post-states / the projection) — NEVER a shared per-credit counter every credit increments (that
//!   would serialize the credit path under lock/atomic even though the result stays order-insensitive).
//!   A state-machine cannot see runtime contention, so C5's "scales" is a held DESIGN condition on §11 +
//!   the conservation monitor (derived aggregates), not something proven here; only "commutes" is proven.
//! - **C6 non-vacuous** — a credit AND a debit-after-consolidation are both reachable.
//!
//! C3/C4/C6 are stateright properties over every interleaving; C1/C2/C5 are structural tests over the
//! pure transition helpers (they are properties of the transition FUNCTION, not of any one state).

use stateright::{Model, Property};

/// The sharded hot-account state: N credit-only sub-accounts, one primary, and the running credit/debit
/// totals. NOTE (C5-R1): `total_credited_chirho`/`total_debited_chirho` are MODELING aggregates that make
/// C4 conservation checkable as a state property — they are NOT a runtime write-path counter. The real
/// impl derives the global aggregates at read time; only per-account post-state rides the write path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StateCChirho {
    pub subs_chirho: Vec<u32>,
    pub primary_chirho: u32,
    pub total_credited_chirho: u32,
    pub total_debited_chirho: u32,
}

/// Credit sub-account `sub` by `amount`. C2: touches ONLY `subs[sub]` (and the global credit total) —
/// it never reads or writes any other sub-account or the primary.
pub fn apply_credit_chirho(
    mut state_chirho: StateCChirho,
    sub_chirho: usize,
    amount_chirho: u32,
) -> StateCChirho {
    state_chirho.subs_chirho[sub_chirho] += amount_chirho;
    state_chirho.total_credited_chirho += amount_chirho;
    state_chirho
}

/// Consolidate sub-account `sub` into the primary — an ordinary conserving transfer (sub -> primary).
pub fn apply_consolidate_chirho(mut state_chirho: StateCChirho, sub_chirho: usize) -> StateCChirho {
    state_chirho.primary_chirho += state_chirho.subs_chirho[sub_chirho];
    state_chirho.subs_chirho[sub_chirho] = 0;
    state_chirho
}

/// Debit `amount` from the PRIMARY only (C3: never reads a cross-shard sum). Returns `None` if the
/// primary is underfunded — the caller must consolidate first — so an over-debit is never accepted (F4).
pub fn try_apply_debit_chirho(
    state_chirho: &StateCChirho,
    amount_chirho: u32,
) -> Option<StateCChirho> {
    if state_chirho.primary_chirho < amount_chirho {
        return None;
    }
    let mut next_chirho = state_chirho.clone();
    next_chirho.primary_chirho -= amount_chirho;
    next_chirho.total_debited_chirho += amount_chirho;
    Some(next_chirho)
}

/// Model C configuration — `num_subs` credit-only sub-accounts, bounded to `max_credited` unit credits
/// for a finite, exhaustively-checkable state space. Credits and debits are unit (1).
pub struct ModelCChirho {
    pub num_subs_chirho: usize,
    pub max_credited_chirho: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ActionCChirho {
    CreditChirho { sub_chirho: usize },
    ConsolidateChirho { sub_chirho: usize },
    DebitChirho,
}

impl Model for ModelCChirho {
    type State = StateCChirho;
    type Action = ActionCChirho;

    fn init_states(&self) -> Vec<Self::State> {
        vec![StateCChirho {
            subs_chirho: vec![0; self.num_subs_chirho],
            primary_chirho: 0,
            total_credited_chirho: 0,
            total_debited_chirho: 0,
        }]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        // A unit credit to any sub (bounded by max_credited) — always available on the credit path.
        if state.total_credited_chirho < self.max_credited_chirho {
            for sub_chirho in 0..self.num_subs_chirho {
                actions.push(ActionCChirho::CreditChirho { sub_chirho });
            }
        }
        // Consolidate any non-empty sub into the primary.
        for sub_chirho in 0..self.num_subs_chirho {
            if state.subs_chirho[sub_chirho] > 0 {
                actions.push(ActionCChirho::ConsolidateChirho { sub_chirho });
            }
        }
        // Debit a unit from the primary (enabled iff funded — the fold requirement is exercised).
        if state.primary_chirho >= 1 {
            actions.push(ActionCChirho::DebitChirho);
        }
    }

    fn next_state(&self, last_state: &Self::State, action: Self::Action) -> Option<Self::State> {
        match action {
            ActionCChirho::CreditChirho { sub_chirho } => {
                if last_state.total_credited_chirho >= self.max_credited_chirho {
                    return None;
                }
                Some(apply_credit_chirho(last_state.clone(), sub_chirho, 1))
            }
            ActionCChirho::ConsolidateChirho { sub_chirho } => {
                if last_state.subs_chirho[sub_chirho] == 0 {
                    return None;
                }
                Some(apply_consolidate_chirho(last_state.clone(), sub_chirho))
            }
            ActionCChirho::DebitChirho => try_apply_debit_chirho(last_state, 1),
        }
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            // C4: conservation across the fan-out. Checked underflow-safe (add debited to the left).
            Property::<Self>::always("c4-conservation-across-shards-chirho", |_, state| {
                let held_chirho: u32 = state.subs_chirho.iter().sum::<u32>() + state.primary_chirho;
                held_chirho + state.total_debited_chirho == state.total_credited_chirho
            }),
            // C3/F4: no over-debit ever — globally you cannot have debited more than was credited.
            Property::<Self>::always("c3-no-over-debit-fold-chirho", |_, state| {
                state.total_debited_chirho <= state.total_credited_chirho
            }),
            // C6: non-vacuous — a credit AND a debit-after-consolidation are both reachable (a debit is
            // only possible after a consolidation funds the primary, so this exercises the whole fold).
            Property::<Self>::sometimes(
                "c6-credit-and-folded-debit-reachable-chirho",
                |_, state| state.total_credited_chirho > 0 && state.total_debited_chirho > 0,
            ),
        ]
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use stateright::Checker;

    fn state_chirho(subs_chirho: Vec<u32>, primary_chirho: u32) -> StateCChirho {
        let credited_chirho = subs_chirho.iter().sum::<u32>() + primary_chirho;
        StateCChirho {
            subs_chirho,
            primary_chirho,
            total_credited_chirho: credited_chirho,
            total_debited_chirho: 0,
        }
    }

    // C3/C4/C6 — exhaustive over every credit/consolidate/debit interleaving.
    #[test]
    fn model_c_conservation_fold_and_liveness_hold_exhaustively_chirho() {
        ModelCChirho {
            num_subs_chirho: 2,
            max_credited_chirho: 3,
        }
        .checker()
        .spawn_bfs()
        .join()
        .assert_properties();
    }

    // C1 — credits to different sub-accounts commute (CRDT diamond): either order, same state.
    #[test]
    fn c1_credits_to_different_subs_commute_chirho() {
        let base_chirho = state_chirho(vec![0, 0], 0);
        let zero_then_one_chirho =
            apply_credit_chirho(apply_credit_chirho(base_chirho.clone(), 0, 1), 1, 1);
        let one_then_zero_chirho =
            apply_credit_chirho(apply_credit_chirho(base_chirho.clone(), 1, 1), 0, 1);
        assert_eq!(zero_then_one_chirho, one_then_zero_chirho);
    }

    // C2 — a credit to sub i touches ONLY sub i (no cross-shard read/write; primary untouched).
    #[test]
    fn c2_credit_touches_only_its_sub_chirho() {
        let base_chirho = state_chirho(vec![5, 7, 9], 3);
        let after_chirho = apply_credit_chirho(base_chirho.clone(), 1, 4);
        assert_eq!(after_chirho.subs_chirho[0], base_chirho.subs_chirho[0]);
        assert_eq!(after_chirho.subs_chirho[2], base_chirho.subs_chirho[2]);
        assert_eq!(after_chirho.primary_chirho, base_chirho.primary_chirho);
        assert_eq!(after_chirho.subs_chirho[1], base_chirho.subs_chirho[1] + 4);
    }

    // C5 — the escape scales: N independent sub-account credits are order-insensitive (no single
    // serialization point every credit must pass), so throughput grows with N.
    #[test]
    fn c5_credits_scale_independently_across_n_subs_chirho() {
        let base_chirho = state_chirho(vec![0; 4], 0);
        let order_a_chirho = [0usize, 1, 2, 3]
            .iter()
            .fold(base_chirho.clone(), |s_chirho, &i_chirho| {
                apply_credit_chirho(s_chirho, i_chirho, 1)
            });
        let order_b_chirho = [3usize, 1, 0, 2]
            .iter()
            .fold(base_chirho.clone(), |s_chirho, &i_chirho| {
                apply_credit_chirho(s_chirho, i_chirho, 1)
            });
        assert_eq!(order_a_chirho, order_b_chirho);
        assert_eq!(order_a_chirho.subs_chirho.iter().sum::<u32>(), 4);
        assert_eq!(order_a_chirho.total_credited_chirho, 4);
    }

    // C3 detail — a debit is refused when the primary is underfunded (must consolidate first), and
    // never drives a balance negative.
    #[test]
    fn c3_debit_refused_until_primary_funded_chirho() {
        // Credits sit in a sub; the primary is empty -> debit refused.
        let credited_chirho = state_chirho(vec![2, 0], 0);
        assert!(try_apply_debit_chirho(&credited_chirho, 1).is_none());
        // Consolidate sub 0 -> primary, then the debit succeeds and conserves.
        let folded_chirho = apply_consolidate_chirho(credited_chirho, 0);
        let debited_chirho = try_apply_debit_chirho(&folded_chirho, 1).unwrap();
        assert_eq!(debited_chirho.primary_chirho, 1);
        assert_eq!(debited_chirho.total_debited_chirho, 1);
        // Over-debit beyond the primary is refused.
        assert!(try_apply_debit_chirho(&debited_chirho, 2).is_none());
    }
}
