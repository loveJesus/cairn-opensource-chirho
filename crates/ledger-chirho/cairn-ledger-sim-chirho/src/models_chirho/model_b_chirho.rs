// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Model B — the toy log's crash-recoverable rotation protocol, exhaustively model-checked with
//! stateright.
//!
//! An ABSTRACT complement to the concrete sim crash-matrix: a state machine over one log's durable
//! rotation state (marker present, the active file's presence + record count, the sealed segments,
//! and the total records ever appended). Every interleaving of append / start-rotate / seal /
//! fresh-active / clear-marker / recover is explored to a small bound. `Recover` may fire from ANY
//! marker-present state (modeling a crash at any cut followed by restart), and appends + rotations
//! are refused while a marker is pending (reads-refused-during-pending is structural in the guards).
//!
//! Properties, checked across every interleaving:
//! - **R1** — records are conserved: active_records + sum(segments) == total ever appended. Nothing
//!   is lost or duplicated by a rotation or a crash-recovery.
//! - **R2** — a fully clean, fully-recovered state (marker cleared, records sealed in a segment) is
//!   reachable: recovery converges rather than wedging.
//! - **R3 / no-wedge** — no reachable state is the unrecoverable wedge (marker present, active absent,
//!   and no segment) — the R-3b-1 failure. The empty-active rotate guard makes it unconstructible.
//! - **no-empty-segment** — no sealed segment is empty (the R-3b-1 seq-resurrection door stays shut).

use stateright::{Model, Property};

/// One log's durable rotation state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StateBChirho {
    pub marker_chirho: bool,
    pub active_present_chirho: bool,
    pub active_records_chirho: u32,
    pub segments_chirho: Vec<u32>,
    pub total_appended_chirho: u32,
}

/// A durable transition — the rotation cuts, an append, or a restart-recovery.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ActionBChirho {
    AppendChirho,
    StartRotateChirho,
    SealChirho,
    FreshActiveChirho,
    ClearMarkerChirho,
    RecoverChirho,
}

/// Model B configuration — bounded to `max_records` total appends for a finite state space.
pub struct ModelBChirho {
    pub max_records_chirho: u32,
}

impl Model for ModelBChirho {
    type State = StateBChirho;
    type Action = ActionBChirho;

    fn init_states(&self) -> Vec<Self::State> {
        vec![StateBChirho {
            marker_chirho: false,
            active_present_chirho: true,
            active_records_chirho: 0,
            segments_chirho: Vec::new(),
            total_appended_chirho: 0,
        }]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        // While a rotation is pending (marker set), only cuts + recovery are offered — appends and new
        // rotations are refused (reads-refused-during-pending). Recover may always fire from a pending
        // state, modeling a crash-at-any-cut then restart.
        if state.marker_chirho {
            actions.push(ActionBChirho::SealChirho);
            actions.push(ActionBChirho::FreshActiveChirho);
            actions.push(ActionBChirho::ClearMarkerChirho);
            actions.push(ActionBChirho::RecoverChirho);
        } else {
            if state.total_appended_chirho < self.max_records_chirho {
                actions.push(ActionBChirho::AppendChirho);
            }
            actions.push(ActionBChirho::StartRotateChirho);
        }
    }

    fn next_state(&self, last_state: &Self::State, action: Self::Action) -> Option<Self::State> {
        match action {
            ActionBChirho::AppendChirho => {
                if last_state.marker_chirho
                    || !last_state.active_present_chirho
                    || last_state.total_appended_chirho >= self.max_records_chirho
                {
                    return None;
                }
                let mut next_chirho = last_state.clone();
                next_chirho.active_records_chirho += 1;
                next_chirho.total_appended_chirho += 1;
                Some(next_chirho)
            }
            ActionBChirho::StartRotateChirho => {
                // R-3b-1: refuse to rotate an absent or EMPTY active — no marker is written, so no
                // wedge and no empty segment can ever be constructed.
                if last_state.marker_chirho
                    || !last_state.active_present_chirho
                    || last_state.active_records_chirho == 0
                {
                    return None;
                }
                let mut next_chirho = last_state.clone();
                next_chirho.marker_chirho = true;
                Some(next_chirho)
            }
            ActionBChirho::SealChirho => {
                if !last_state.marker_chirho
                    || !last_state.active_present_chirho
                    || last_state.active_records_chirho == 0
                {
                    return None;
                }
                let mut next_chirho = last_state.clone();
                next_chirho
                    .segments_chirho
                    .push(last_state.active_records_chirho);
                next_chirho.active_present_chirho = false;
                next_chirho.active_records_chirho = 0;
                Some(next_chirho)
            }
            ActionBChirho::FreshActiveChirho => {
                if !last_state.marker_chirho || last_state.active_present_chirho {
                    return None;
                }
                let mut next_chirho = last_state.clone();
                next_chirho.active_present_chirho = true;
                next_chirho.active_records_chirho = 0;
                Some(next_chirho)
            }
            ActionBChirho::ClearMarkerChirho => {
                if !last_state.marker_chirho
                    || !last_state.active_present_chirho
                    || last_state.active_records_chirho != 0
                    || last_state.segments_chirho.is_empty()
                {
                    return None;
                }
                let mut next_chirho = last_state.clone();
                next_chirho.marker_chirho = false;
                Some(next_chirho)
            }
            ActionBChirho::RecoverChirho => {
                if !last_state.marker_chirho {
                    return None;
                }
                let mut next_chirho = last_state.clone();
                if last_state.active_present_chirho && last_state.active_records_chirho > 0 {
                    // Crashed after the marker, before the seal — finish seal + fresh active + clear.
                    next_chirho
                        .segments_chirho
                        .push(last_state.active_records_chirho);
                    next_chirho.active_present_chirho = true;
                    next_chirho.active_records_chirho = 0;
                    next_chirho.marker_chirho = false;
                } else if !last_state.active_present_chirho {
                    // Crashed after the seal, before the fresh active — finish fresh active + clear.
                    if last_state.segments_chirho.is_empty() {
                        // Unrecoverable wedge: no active, no segment. Refuse (R3). Unreachable under
                        // the R-3b-1 guard; the no-wedge property proves it never happens.
                        return None;
                    }
                    next_chirho.active_present_chirho = true;
                    next_chirho.active_records_chirho = 0;
                    next_chirho.marker_chirho = false;
                } else {
                    // Fresh active exists (present, empty), segment sealed — finish clear.
                    next_chirho.marker_chirho = false;
                }
                Some(next_chirho)
            }
        }
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::<Self>::always("r1-records-conserved-chirho", |_, state| {
                let sealed_chirho: u32 = state.segments_chirho.iter().sum();
                state.active_records_chirho + sealed_chirho == state.total_appended_chirho
            }),
            Property::<Self>::always("r3-no-unrecoverable-wedge-chirho", |_, state| {
                !(state.marker_chirho
                    && !state.active_present_chirho
                    && state.segments_chirho.is_empty())
            }),
            Property::<Self>::always("no-empty-segment-chirho", |_, state| {
                state
                    .segments_chirho
                    .iter()
                    .all(|seg_chirho| *seg_chirho > 0)
            }),
            Property::<Self>::sometimes("r2-recovery-reaches-clean-sealed-chirho", |_, state| {
                !state.marker_chirho
                    && !state.segments_chirho.is_empty()
                    && state.active_records_chirho == 0
            }),
        ]
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use stateright::Checker;

    #[test]
    fn model_b_rotation_recovery_holds_exhaustively_chirho() {
        // Up to 2 records total — enough for append, rotate, refill, re-rotate, and a crash + recover
        // at every cut; every interleaving checked in full.
        ModelBChirho {
            max_records_chirho: 2,
        }
        .checker()
        .spawn_bfs()
        .join()
        .assert_properties();
    }
}
