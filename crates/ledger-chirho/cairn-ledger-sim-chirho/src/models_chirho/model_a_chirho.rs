// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Model A — the toy log's epoch-fence AND spendable-balance protocol, exhaustively model-checked
//! with stateright.
//!
//! An ABSTRACT complement to the concrete sim crash-matrix: a state machine over a SHARD of sibling
//! logs, a directory that grants monotone shard epochs, and owners appending unit credit/debit ops
//! under any lease (current, stale, OR forged-future — the actions offer them all; the fence in
//! `next_state` decides). The append law is R-3a-1 (`e == E`, the current shard lease) plus
//! chain-monotonicity, and a debit is fenced if it would drive the log's balance negative.
//!
//! Properties, checked across every interleaving:
//! - **F2** — epochs are monotone non-decreasing along each log's sequence.
//! - **F3** — no sibling log ever holds a record whose epoch exceeds the granted shard epoch (the
//!   future/never-granted-epoch split-brain hole R-3a-1 closes); one shared grant fences every sibling.
//! - **F4** — every log's balance (credits − debits) stays >= 0: no over-debit is ever accepted. This
//!   is the spendable law (`C − D >= amount`) that the Brick 2.1 signed record's one-signed-read
//!   check formalizes, exercised here at toy scale with unit ops.
//! - **F-live** — some append is reachable (the fences are not vacuously safe by rejecting all).
//!
//! F1 (each seq appended once, no gap/dup) is structural: a record's seq IS its vector index.

use stateright::{Model, Property};

/// A unit ledger operation on a log.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum OpChirho {
    CreditChirho,
    DebitChirho,
}

/// One sibling log's accepted chain — each record's `(epoch, op)`, its seq being the vector index.
type LogRecordsChirho = Vec<(u64, OpChirho)>;

/// The model-checked state: the shard's currently-granted epoch + every sibling log's chain.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StateAChirho {
    pub granted_epoch_chirho: u64,
    pub logs_chirho: Vec<LogRecordsChirho>,
}

/// A transition: the directory grants the next shard epoch, or an owner holding `lease` attempts a
/// credit/debit append to a sibling log.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ActionAChirho {
    GrantEpochChirho,
    AppendChirho {
        log_chirho: usize,
        lease_chirho: u64,
        op_chirho: OpChirho,
    },
}

/// Model A configuration — a shard of `num_logs` sibling logs, bounded to `max_epoch` grants and
/// `max_records` per log so the reachable state space is finite and exhaustively checkable.
pub struct ModelAChirho {
    pub num_logs_chirho: usize,
    pub max_epoch_chirho: u64,
    pub max_records_chirho: usize,
}

fn credits_debits_chirho(log_chirho: &LogRecordsChirho) -> (usize, usize) {
    let credits_chirho = log_chirho
        .iter()
        .filter(|(_, op_chirho)| *op_chirho == OpChirho::CreditChirho)
        .count();
    (credits_chirho, log_chirho.len() - credits_chirho)
}

impl Model for ModelAChirho {
    type State = StateAChirho;
    type Action = ActionAChirho;

    fn init_states(&self) -> Vec<Self::State> {
        vec![StateAChirho {
            granted_epoch_chirho: 0,
            logs_chirho: vec![Vec::new(); self.num_logs_chirho],
        }]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        // The directory may grant the next shard epoch (bounded for finiteness).
        if state.granted_epoch_chirho < self.max_epoch_chirho {
            actions.push(ActionAChirho::GrantEpochChirho);
        }
        // Offer EVERY lease in 0..=max_epoch — current, stale, AND forged-future — with each op, to
        // any not-yet-full log. The fence in next_state decides; a rejected append is a no-transition,
        // so the reachable graph contains only lawful states while every attack is exercised.
        for log_index_chirho in 0..self.num_logs_chirho {
            if state.logs_chirho[log_index_chirho].len() < self.max_records_chirho {
                for lease_chirho in 0..=self.max_epoch_chirho {
                    for op_chirho in [OpChirho::CreditChirho, OpChirho::DebitChirho] {
                        actions.push(ActionAChirho::AppendChirho {
                            log_chirho: log_index_chirho,
                            lease_chirho,
                            op_chirho,
                        });
                    }
                }
            }
        }
    }

    fn next_state(&self, last_state: &Self::State, action: Self::Action) -> Option<Self::State> {
        match action {
            ActionAChirho::GrantEpochChirho => {
                if last_state.granted_epoch_chirho >= self.max_epoch_chirho {
                    return None;
                }
                let mut next_chirho = last_state.clone();
                next_chirho.granted_epoch_chirho += 1;
                Some(next_chirho)
            }
            ActionAChirho::AppendChirho {
                log_chirho,
                lease_chirho,
                op_chirho,
            } => {
                let log_ref_chirho = &last_state.logs_chirho[log_chirho];
                if log_ref_chirho.len() >= self.max_records_chirho {
                    return None;
                }
                let chain_fence_chirho = log_ref_chirho
                    .last()
                    .map(|(e_chirho, _)| *e_chirho)
                    .unwrap_or(0);
                // R-3a-1: the record must carry the CURRENT shard lease (e == E); a stale or
                // forged-future lease is fenced out (no transition), as is a lease below the chain tail.
                if lease_chirho != last_state.granted_epoch_chirho
                    || lease_chirho < chain_fence_chirho
                {
                    return None;
                }
                // F4: a debit that would drive the balance negative (over-debit) is fenced out — this
                // is the spendable law at unit scale.
                if op_chirho == OpChirho::DebitChirho {
                    let (credits_chirho, debits_chirho) = credits_debits_chirho(log_ref_chirho);
                    if debits_chirho >= credits_chirho {
                        return None;
                    }
                }
                let mut next_chirho = last_state.clone();
                next_chirho.logs_chirho[log_chirho].push((lease_chirho, op_chirho));
                Some(next_chirho)
            }
        }
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::<Self>::always("f2-epochs-monotone-chirho", |_, state| {
                state.logs_chirho.iter().all(|log_chirho| {
                    log_chirho
                        .windows(2)
                        .all(|pair_chirho| pair_chirho[0].0 <= pair_chirho[1].0)
                })
            }),
            Property::<Self>::always("f3-no-future-epoch-across-siblings-chirho", |_, state| {
                state.logs_chirho.iter().all(|log_chirho| {
                    log_chirho
                        .iter()
                        .all(|(epoch_chirho, _)| *epoch_chirho <= state.granted_epoch_chirho)
                })
            }),
            Property::<Self>::always("f4-balance-non-negative-chirho", |_, state| {
                state.logs_chirho.iter().all(|log_chirho| {
                    let (credits_chirho, debits_chirho) = credits_debits_chirho(log_chirho);
                    credits_chirho >= debits_chirho
                })
            }),
            Property::<Self>::sometimes("f-live-some-append-succeeds-chirho", |_, state| {
                state
                    .logs_chirho
                    .iter()
                    .any(|log_chirho| !log_chirho.is_empty())
            }),
        ]
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use stateright::Checker;

    #[test]
    fn model_a_epoch_fence_and_balance_hold_exhaustively_chirho() {
        // A shard of 2 sibling logs, 2 grants, 3 records/log — every lease (current/stale/future) x op
        // interleaving, checked in full.
        ModelAChirho {
            num_logs_chirho: 2,
            max_epoch_chirho: 2,
            max_records_chirho: 3,
        }
        .checker()
        .spawn_bfs()
        .join()
        .assert_properties();
    }
}
