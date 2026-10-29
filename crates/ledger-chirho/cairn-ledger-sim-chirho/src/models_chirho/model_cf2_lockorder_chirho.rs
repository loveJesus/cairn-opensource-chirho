// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! CF2 no-deadlock keystone — the canonical lock order (§12: multi-log acquisition strictly by
//! log-id-digest ASCENDING) kills deadlock, model-checked with stateright and PROVEN load-bearing
//! by an unordered mutation twin.
//!
//! A cross-cluster / multi-party transfer must lock more than one account-log (its `from` and `to`,
//! plus fee/settlement legs). Two transfers touching the SAME two logs in opposite natural order can
//! circular-wait (T0 holds log A waits log B; T1 holds log B waits log A) — the classic deadlock.
//! §12's law: the saga initiator acquires locks strictly by ascending log-id, so BOTH transfers
//! reach for the lower log first and serialize — no cycle is possible.
//!
//! Properties (over every interleaving of two transfers contending for the same two logs):
//! - **no-deadlock (always, ordered)** — every reachable state is either all-complete OR has a
//!   progress action enabled; a stuck non-terminal state is never reachable.
//! - **live (sometimes)** — both transfers complete (the ordering is not vacuously safe by wedging).
//!
//! MUTATION-RIGOR TWIN: an `unordered` mode lets a transfer grab a higher log before a lower one;
//! the twin proves a STUCK deadlock state is then REACHABLE — so the ascending-order rule is
//! load-bearing.
//!
//! Second-seat notes (claude2 C2.7, #4569):
//! - **Total order (why blake3, not the leg-list order):** deadlock-freedom needs a STRICT TOTAL
//!   order over logs. The concrete key is the log-id BLAKE3 digest — a deterministic function of the
//!   log id, NOT the attacker-controlled leg-list order — and distinct log ids give distinct digests
//!   (no ties). A tie would make two logs order-indistinguishable and reintroduce a cycle; the
//!   concrete build pins that no two distinct logs present equal ordering keys.
//! - **N-generalization (why 2×2 suffices):** this checks the MINIMAL deadlock (2 transfers, 2
//!   logs). No-deadlock for N transfers is the standard resource-ordering argument, not a bigger
//!   model: any wait-cycle contains a transfer holding the globally-lowest held-in-the-cycle log
//!   while waiting for a HIGHER one — impossible under acquire-lowest-unheld-first. So "no-deadlock"
//!   here is the general property, not a claim proven only at N=2.
//! - **C2.3 × C2.7 interaction (concrete-build obligation):** a lock-WAITING transfer still holds
//!   its escrow HOLD; the durable TTL (the C2.3 no-lost-hold timer) must NOT prematurely auto-release
//!   that hold while it blocks on a lower log, or the auto-release fights the in-flight acquisition
//!   (a released hold whose transfer then acquires + credits = phantom). The combined build either
//!   pauses the TTL clock while lock-blocked or has auto-release cleanly abort the pending
//!   acquisition — modeled in the combined TTL+lock model at build.

use stateright::{Model, Property};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StateLockChirho {
    /// Owner transfer of each log, or `None` if free.
    pub lock_owner_chirho: Vec<Option<usize>>,
    /// The logs each transfer currently holds (kept sorted).
    pub holds_chirho: Vec<Vec<usize>>,
    pub done_chirho: Vec<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ActionLockChirho {
    AcquireChirho {
        transfer_chirho: usize,
        log_chirho: usize,
    },
    CompleteChirho {
        transfer_chirho: usize,
    },
}

/// Model config: each transfer's sorted needed logs, and whether the ascending lock order is
/// enforced. `ordered = false` is the mutation twin.
pub struct ModelCf2LockChirho {
    pub num_logs_chirho: usize,
    pub needs_chirho: Vec<Vec<usize>>,
    pub ordered_chirho: bool,
}

impl ModelCf2LockChirho {
    /// The logs transfer `t` still needs (in `needs`, not yet held).
    fn unheld_needed_chirho(&self, state: &StateLockChirho, transfer_chirho: usize) -> Vec<usize> {
        self.needs_chirho[transfer_chirho]
            .iter()
            .copied()
            .filter(|log_chirho| !state.holds_chirho[transfer_chirho].contains(log_chirho))
            .collect()
    }

    /// Is any progress action (an acquire or a complete) enabled anywhere? (Deadlock = a
    /// non-terminal state where this is false.)
    fn has_progress_chirho(&self, state: &StateLockChirho) -> bool {
        (0..self.needs_chirho.len()).any(|transfer_chirho| {
            if state.done_chirho[transfer_chirho] {
                return false;
            }
            let unheld_chirho = self.unheld_needed_chirho(state, transfer_chirho);
            if unheld_chirho.is_empty() {
                return true; // holds all its needed logs → can complete
            }
            // Under the ascending-order rule, ONLY the minimum unheld needed log may be acquired;
            // unordered, any free unheld needed log may be.
            if self.ordered_chirho {
                let min_chirho = *unheld_chirho.iter().min().expect("non-empty");
                state.lock_owner_chirho[min_chirho].is_none()
            } else {
                unheld_chirho
                    .iter()
                    .any(|log_chirho| state.lock_owner_chirho[*log_chirho].is_none())
            }
        })
    }
}

impl Model for ModelCf2LockChirho {
    type State = StateLockChirho;
    type Action = ActionLockChirho;

    fn init_states(&self) -> Vec<Self::State> {
        vec![StateLockChirho {
            lock_owner_chirho: vec![None; self.num_logs_chirho],
            holds_chirho: vec![Vec::new(); self.needs_chirho.len()],
            done_chirho: vec![false; self.needs_chirho.len()],
        }]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        for transfer_chirho in 0..self.needs_chirho.len() {
            if state.done_chirho[transfer_chirho] {
                continue;
            }
            let unheld_chirho = self.unheld_needed_chirho(state, transfer_chirho);
            if unheld_chirho.is_empty() {
                actions.push(ActionLockChirho::CompleteChirho { transfer_chirho });
                continue;
            }
            let acquirable_chirho: Vec<usize> = if self.ordered_chirho {
                // Only the minimum unheld needed log (strict ascending acquisition).
                let min_chirho = *unheld_chirho.iter().min().expect("non-empty");
                vec![min_chirho]
            } else {
                unheld_chirho.clone()
            };
            for log_chirho in acquirable_chirho {
                if state.lock_owner_chirho[log_chirho].is_none() {
                    actions.push(ActionLockChirho::AcquireChirho {
                        transfer_chirho,
                        log_chirho,
                    });
                }
            }
        }
    }

    fn next_state(&self, state: &Self::State, action: Self::Action) -> Option<Self::State> {
        let mut next_chirho = state.clone();
        match action {
            ActionLockChirho::AcquireChirho {
                transfer_chirho,
                log_chirho,
            } => {
                next_chirho.lock_owner_chirho[log_chirho] = Some(transfer_chirho);
                next_chirho.holds_chirho[transfer_chirho].push(log_chirho);
                next_chirho.holds_chirho[transfer_chirho].sort_unstable();
            }
            ActionLockChirho::CompleteChirho { transfer_chirho } => {
                next_chirho.done_chirho[transfer_chirho] = true;
                for log_chirho in &self.needs_chirho[transfer_chirho] {
                    next_chirho.lock_owner_chirho[*log_chirho] = None;
                }
                next_chirho.holds_chirho[transfer_chirho].clear();
            }
        }
        Some(next_chirho)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        if self.ordered_chirho {
            vec![
                Property::<Self>::always("no-deadlock-chirho", |model_chirho, state| {
                    // Not stuck: all-done, OR some progress action is enabled.
                    state.done_chirho.iter().all(|done_chirho| *done_chirho)
                        || model_chirho.has_progress_chirho(state)
                }),
                Property::<Self>::sometimes("live-all-complete-chirho", |_, state| {
                    state.done_chirho.iter().all(|done_chirho| *done_chirho)
                }),
            ]
        } else {
            vec![
                Property::<Self>::sometimes(
                    "deadlock-reachable-unordered-chirho",
                    |model_chirho, state| {
                        // A stuck NON-terminal state: some transfer incomplete, yet no progress action
                        // is enabled anywhere — the circular wait the lock order forbids.
                        state.done_chirho.iter().any(|done_chirho| !*done_chirho)
                            && !model_chirho.has_progress_chirho(state)
                    },
                ),
                Property::<Self>::sometimes("live-all-complete-chirho", |_, state| {
                    state.done_chirho.iter().all(|done_chirho| *done_chirho)
                }),
            ]
        }
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use stateright::Checker;

    /// Two transfers each needing BOTH logs {0,1} — the maximal-contention case (A→B and B→A share
    /// the same two account-logs in opposite natural order).
    fn two_contending_transfers_chirho() -> Vec<Vec<usize>> {
        vec![vec![0, 1], vec![0, 1]]
    }

    #[test]
    fn cf2_ascending_lock_order_is_deadlock_free_chirho() {
        ModelCf2LockChirho {
            num_logs_chirho: 2,
            needs_chirho: two_contending_transfers_chirho(),
            ordered_chirho: true,
        }
        .checker()
        .spawn_bfs()
        .join()
        .assert_properties();
    }

    #[test]
    fn cf2_unordered_acquisition_can_deadlock_chirho() {
        // The mutation twin: WITHOUT the ascending rule, the model checker FINDS the circular-wait
        // stuck state — proving the lock order is load-bearing, not an assumed nicety.
        ModelCf2LockChirho {
            num_logs_chirho: 2,
            needs_chirho: two_contending_transfers_chirho(),
            ordered_chirho: false,
        }
        .checker()
        .spawn_bfs()
        .join()
        .assert_properties();
    }
}
