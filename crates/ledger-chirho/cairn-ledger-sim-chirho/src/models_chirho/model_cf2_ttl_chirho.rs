// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! CF2 no-lost-hold keystone (claude2 C2.3, second-seat #4568) — the DURABLE TTL timer is what
//! guarantees a hold is never stranded when the cross-cluster Credit never arrives (peer down) and
//! the initiator never manually aborts. Model-checked with stateright + a mutation twin proving the
//! TTL load-bearing.
//!
//! The escrow keystone (`model_cf2_transfer`) proves the aborts (Release/Compensate) CONSERVE *if
//! invoked* — but not that a hold STUCK in `Held` is ever released. In the real cross-cluster flow
//! a hold waits for a network round-trip; if the peer is down AND the initiator doesn't actively
//! abort (it may be waiting or crashed), only the DURABLE TTL timer (§4.4, swept on the active log)
//! auto-releases it. Without the TTL the held amount strands until a human notices (the C2.3 trap).
//!
//! Worst-case scenario modeled: the peer never credits (no `Credit` action) and there is no manual
//! abort (no `Release` action) — the TtlExpire timer is the ONLY escape.
//! - **no-lost-hold (always, ttl on)** — a held amount is never permanently stranded: every `Held`
//!   transfer can still `TtlExpire` (so `held` is always clearable), and all holds reach terminal.
//! - **held-strands-without-ttl (sometimes, ttl off)** — a state with a hold stuck in `Held`,
//!   `held > 0`, and NO enabled action IS reachable: the lost hold the TTL prevents.

use stateright::{Model, Property};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HoldPhaseChirho {
    InitChirho,
    HeldChirho,
    ReleasedChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StateTtlChirho {
    /// Each source account's held amount (unit-scale).
    pub held_chirho: Vec<u64>,
    pub phases_chirho: Vec<HoldPhaseChirho>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ActionTtlChirho {
    HoldChirho { transfer_chirho: usize },
    TtlExpireChirho { transfer_chirho: usize },
}

/// Config: how many holds, and whether the durable TTL timer exists. `ttl_enabled = false` is the
/// mutation twin (no auto-release, peer down, no manual abort → strand).
pub struct ModelCf2TtlChirho {
    pub num_holds_chirho: usize,
    pub ttl_enabled_chirho: bool,
}

impl ModelCf2TtlChirho {
    /// Can any progress action fire? (A stuck non-terminal state — a stranded hold — is one where
    /// this is false.)
    fn has_progress_chirho(&self, state: &StateTtlChirho) -> bool {
        state
            .phases_chirho
            .iter()
            .enumerate()
            .any(|(index_chirho, phase_chirho)| {
                match phase_chirho {
                    HoldPhaseChirho::InitChirho => true, // can Hold
                    HoldPhaseChirho::HeldChirho => self.ttl_enabled_chirho, // can TtlExpire iff TTL exists
                    HoldPhaseChirho::ReleasedChirho => {
                        let _ = index_chirho;
                        false
                    }
                }
            })
    }
}

impl Model for ModelCf2TtlChirho {
    type State = StateTtlChirho;
    type Action = ActionTtlChirho;

    fn init_states(&self) -> Vec<Self::State> {
        vec![StateTtlChirho {
            held_chirho: vec![0; self.num_holds_chirho],
            phases_chirho: vec![HoldPhaseChirho::InitChirho; self.num_holds_chirho],
        }]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        for transfer_chirho in 0..self.num_holds_chirho {
            match state.phases_chirho[transfer_chirho] {
                HoldPhaseChirho::InitChirho => {
                    actions.push(ActionTtlChirho::HoldChirho { transfer_chirho });
                }
                HoldPhaseChirho::HeldChirho => {
                    // The peer never credits and the initiator never manually aborts — the ONLY
                    // escape is the durable TTL timer, and only when it exists.
                    if self.ttl_enabled_chirho {
                        actions.push(ActionTtlChirho::TtlExpireChirho { transfer_chirho });
                    }
                }
                HoldPhaseChirho::ReleasedChirho => {}
            }
        }
    }

    fn next_state(&self, state: &Self::State, action: Self::Action) -> Option<Self::State> {
        let mut next_chirho = state.clone();
        match action {
            ActionTtlChirho::HoldChirho { transfer_chirho } => {
                next_chirho.held_chirho[transfer_chirho] += 1;
                next_chirho.phases_chirho[transfer_chirho] = HoldPhaseChirho::HeldChirho;
            }
            ActionTtlChirho::TtlExpireChirho { transfer_chirho } => {
                next_chirho.held_chirho[transfer_chirho] -= 1;
                next_chirho.phases_chirho[transfer_chirho] = HoldPhaseChirho::ReleasedChirho;
            }
        }
        Some(next_chirho)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        if self.ttl_enabled_chirho {
            vec![
                Property::<Self>::always("no-lost-hold-chirho", |model_chirho, state| {
                    // Never permanently stranded: all-terminal OR a progress action is enabled.
                    state
                        .phases_chirho
                        .iter()
                        .all(|phase_chirho| *phase_chirho == HoldPhaseChirho::ReleasedChirho)
                        || model_chirho.has_progress_chirho(state)
                }),
                Property::<Self>::sometimes("live-all-released-held-cleared-chirho", |_, state| {
                    state
                        .phases_chirho
                        .iter()
                        .all(|phase_chirho| *phase_chirho == HoldPhaseChirho::ReleasedChirho)
                        && state
                            .held_chirho
                            .iter()
                            .all(|held_chirho| *held_chirho == 0)
                }),
            ]
        } else {
            vec![Property::<Self>::sometimes(
                "held-strands-without-ttl-chirho",
                |model_chirho, state| {
                    // A stranded hold: a Held transfer with held > 0, and NO action can fire.
                    state.phases_chirho.contains(&HoldPhaseChirho::HeldChirho)
                        && state.held_chirho.iter().any(|held_chirho| *held_chirho > 0)
                        && !model_chirho.has_progress_chirho(state)
                },
            )]
        }
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use stateright::Checker;

    #[test]
    fn cf2_durable_ttl_prevents_lost_hold_chirho() {
        // Peer down, no manual abort: the TTL timer still auto-releases every hold; held clears.
        ModelCf2TtlChirho {
            num_holds_chirho: 2,
            ttl_enabled_chirho: true,
        }
        .checker()
        .spawn_bfs()
        .join()
        .assert_properties();
    }

    #[test]
    fn cf2_without_ttl_a_hold_strands_chirho() {
        // The mutation twin: remove the TTL timer and the checker FINDS a stranded hold (held > 0,
        // stuck in Held, no action) — proving the durable TTL is load-bearing for no-lost-hold.
        ModelCf2TtlChirho {
            num_holds_chirho: 2,
            ttl_enabled_chirho: false,
        }
        .checker()
        .spawn_bfs()
        .join()
        .assert_properties();
    }
}
