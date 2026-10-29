// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Model B-SEQ — the rotation protocol's SEQUENCE-continuity across crash points, model-checked
//! exhaustively with stateright. The MONEY refinement of Model B: Model B conserves records by
//! COUNT, but never models which SEQUENCE each record is assigned. This proves the sequence a record
//! gets is never REUSED and never GAPPED across a seal -> durable-manifest -> reset rotation and a
//! crash-at-any-cut recovery. It is the R2 forged-base seq-reuse class one level up at the
//! seal/manifest grain (claude2 #4604 RC.1/RC.2/RC.4): RC.1 no seq reuse, RC.2 no re-append into a
//! sealed segment, RC.4 contiguous partition (the seq analog of per-kind conservation). It is the
//! ABSTRACT de-risk the B1/B2 real-engine build builds to, NOT a check over the real engine.
//!
//! The intent-first law under test: the just-sealed segment's manifest entry MUST become durable
//! (fold the orphan into the durable manifest) BEFORE a fresh active file is created. Otherwise a
//! crash leaves a sealed orphan the manifest does not name, and a recovery that resets the active at
//! the durable span REUSES the orphan's sequences. The `fold_on_recover_chirho = false` mutation
//! twin removes the fold and the checker FINDS that reuse becomes reachable — proving the intent-first
//! fold load-bearing for no-seq-reuse.

use stateright::{Model, Property};

/// One log's durable rotation state as SEQ-interval structure. Sealed segments are contiguous from
/// seq 0, so durable segment `i` occupies `[sum(counts[..i]), sum(counts[..=i]))`; the base a fresh
/// active opens at is the DURABLE manifest's total span — `derive_base_seq`'s abstraction.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StateBSeqChirho {
    /// Record counts of the sealed segments DURABLE in the manifest (contiguous from seq 0).
    pub durable_segments_chirho: Vec<u32>,
    /// The rotation-in-progress marker — the system's BELIEF that a rotation is mid-flight (appends
    /// refused while set). Distinct from the durable orphan fact: a buggy recovery clears this belief
    /// while the orphan still physically lingers, and appends then resume onto reused sequences.
    pub pending_chirho: bool,
    /// A sealed FILE whose manifest entry is NOT yet durable — the crash-after-seal-before-manifest
    /// window. Its interval is `[durable_span, durable_span + orphan)`. Physically durable on disk.
    pub orphan_count_chirho: Option<u32>,
    /// Is a fresh active file present?
    pub active_present_chirho: bool,
    /// The seq the active file's record 0 maps to (set when the active file is created).
    pub active_base_chirho: u32,
    /// Records in the active file — its interval is `[active_base, active_base + count)`.
    pub active_count_chirho: u32,
    /// Total records ever appended (conservation invariant + finite bound).
    pub total_appended_chirho: u32,
}

impl StateBSeqChirho {
    fn durable_span_chirho(&self) -> u32 {
        self.durable_segments_chirho.iter().sum()
    }

    /// Every occupied seq interval `[start, end)` at this state: the durable segments, the orphan (if
    /// any), and the active file (if present). The no-reuse / contiguity properties read these.
    fn intervals_chirho(&self) -> Vec<(u32, u32)> {
        let mut out_chirho = Vec::new();
        let mut cursor_chirho = 0u32;
        for count_chirho in &self.durable_segments_chirho {
            out_chirho.push((cursor_chirho, cursor_chirho + count_chirho));
            cursor_chirho += *count_chirho;
        }
        if let Some(orphan_chirho) = self.orphan_count_chirho {
            out_chirho.push((cursor_chirho, cursor_chirho + orphan_chirho));
        }
        if self.active_present_chirho {
            out_chirho.push((
                self.active_base_chirho,
                self.active_base_chirho + self.active_count_chirho,
            ));
        }
        out_chirho
    }

    /// No two occupied intervals share a sequence (RC.1 no seq reuse / RC.2 no sealed re-append).
    fn no_seq_reuse_chirho(&self) -> bool {
        let intervals_chirho = self.intervals_chirho();
        for i_chirho in 0..intervals_chirho.len() {
            for j_chirho in (i_chirho + 1)..intervals_chirho.len() {
                let (a0_chirho, a1_chirho) = intervals_chirho[i_chirho];
                let (b0_chirho, b1_chirho) = intervals_chirho[j_chirho];
                // Half-open overlap: max(start) < min(end).
                if a0_chirho.max(b0_chirho) < a1_chirho.min(b1_chirho) {
                    return false;
                }
            }
        }
        true
    }

    /// The occupied intervals tile `[0, total_appended)` with no gap and no overlap (RC.4 — the seq
    /// analog of conservation): sorted by start, each begins exactly where the previous ended.
    fn contiguous_partition_chirho(&self) -> bool {
        let mut intervals_chirho = self.intervals_chirho();
        intervals_chirho.sort_unstable();
        let mut expected_chirho = 0u32;
        for (start_chirho, end_chirho) in intervals_chirho {
            if start_chirho != expected_chirho || end_chirho < start_chirho {
                return false;
            }
            expected_chirho = end_chirho;
        }
        expected_chirho == self.total_appended_chirho
    }
}

/// Model B-SEQ configuration. `fold_on_recover_chirho = true` is the intent-first protocol; `false`
/// is the mutation twin (recovery resets the active WITHOUT first folding the sealed orphan).
pub struct ModelBSeqChirho {
    pub max_records_chirho: u32,
    pub fold_on_recover_chirho: bool,
}

/// A durable transition: an append, the rotation cuts (seal / durable-manifest / fresh-active), or a
/// restart-recovery from a crash at any cut.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ActionBSeqChirho {
    AppendChirho,
    SealChirho,
    ManifestChirho,
    FreshActiveChirho,
    RecoverChirho,
}

impl Model for ModelBSeqChirho {
    type State = StateBSeqChirho;
    type Action = ActionBSeqChirho;

    fn init_states(&self) -> Vec<Self::State> {
        vec![StateBSeqChirho {
            durable_segments_chirho: Vec::new(),
            pending_chirho: false,
            orphan_count_chirho: None,
            active_present_chirho: true,
            active_base_chirho: 0,
            active_count_chirho: 0,
            total_appended_chirho: 0,
        }]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        if state.pending_chirho {
            // A rotation the system BELIEVES is mid-flight: only the completion cuts and a
            // crash-recovery are offered (appends + new rotations refused while pending).
            if state.orphan_count_chirho.is_some() && !state.active_present_chirho {
                actions.push(ActionBSeqChirho::ManifestChirho);
            }
            if state.orphan_count_chirho.is_none() && !state.active_present_chirho {
                actions.push(ActionBSeqChirho::FreshActiveChirho);
            }
            actions.push(ActionBSeqChirho::RecoverChirho);
        } else {
            // The system believes it is steady: it appends and may start a rotation. A lingering
            // orphan here (only reachable via the mutation twin) is INVISIBLE to the system.
            if state.active_present_chirho && state.total_appended_chirho < self.max_records_chirho
            {
                actions.push(ActionBSeqChirho::AppendChirho);
            }
            if state.active_present_chirho
                && state.active_count_chirho > 0
                && state.orphan_count_chirho.is_none()
            {
                actions.push(ActionBSeqChirho::SealChirho);
            }
        }
    }

    fn next_state(&self, last_state: &Self::State, action: Self::Action) -> Option<Self::State> {
        match action {
            ActionBSeqChirho::AppendChirho => {
                // The system appends whenever it believes it is steady (not pending). Its record gets
                // seq `active_base + active_count` — which REUSES an orphan's sequences if a buggy
                // recovery left one lingering under a cleared pending marker.
                if last_state.pending_chirho
                    || !last_state.active_present_chirho
                    || last_state.total_appended_chirho >= self.max_records_chirho
                {
                    return None;
                }
                let mut next_chirho = last_state.clone();
                next_chirho.active_count_chirho += 1;
                next_chirho.total_appended_chirho += 1;
                Some(next_chirho)
            }
            ActionBSeqChirho::SealChirho => {
                // Rename the active file to a sealed orphan: its records leave the active file, but the
                // manifest entry that names them is NOT durable yet (the RC.1 crash window opens here).
                if last_state.pending_chirho
                    || last_state.orphan_count_chirho.is_some()
                    || !last_state.active_present_chirho
                    || last_state.active_count_chirho == 0
                {
                    return None;
                }
                let mut next_chirho = last_state.clone();
                next_chirho.pending_chirho = true;
                next_chirho.orphan_count_chirho = Some(last_state.active_count_chirho);
                next_chirho.active_present_chirho = false;
                next_chirho.active_count_chirho = 0;
                Some(next_chirho)
            }
            ActionBSeqChirho::ManifestChirho => {
                // Fold the orphan into the durable manifest — the base anchor for the next active is
                // now durable (intent-first: this precedes the fresh active). Stays pending.
                if !last_state.pending_chirho || last_state.active_present_chirho {
                    return None;
                }
                let orphan_chirho = last_state.orphan_count_chirho?;
                let mut next_chirho = last_state.clone();
                next_chirho.durable_segments_chirho.push(orphan_chirho);
                next_chirho.orphan_count_chirho = None;
                Some(next_chirho)
            }
            ActionBSeqChirho::FreshActiveChirho => {
                // Create the fresh active file at the DURABLE span and clear pending — only legal once
                // the orphan is folded (orphan None), so the new base already accounts for the segment.
                if !last_state.pending_chirho
                    || last_state.orphan_count_chirho.is_some()
                    || last_state.active_present_chirho
                {
                    return None;
                }
                let mut next_chirho = last_state.clone();
                next_chirho.active_present_chirho = true;
                next_chirho.active_base_chirho = last_state.durable_span_chirho();
                next_chirho.active_count_chirho = 0;
                next_chirho.pending_chirho = false;
                Some(next_chirho)
            }
            ActionBSeqChirho::RecoverChirho => {
                // A crash at any mid-rotation cut, then restart. Only fires while pending; clears the
                // marker (the system considers the rotation resolved after restart).
                if !last_state.pending_chirho {
                    return None;
                }
                let mut next_chirho = last_state.clone();
                if self.fold_on_recover_chirho {
                    // Intent-first recovery: roll the orphan forward into the durable manifest, THEN
                    // open the fresh active at the (now correct) durable span — no seq reuse.
                    if let Some(orphan_chirho) = next_chirho.orphan_count_chirho.take() {
                        next_chirho.durable_segments_chirho.push(orphan_chirho);
                    }
                } else if !next_chirho.active_present_chirho {
                    // MUTATION TWIN: reset the active at the durable span WITHOUT folding the orphan.
                    // The manifest still omits the orphan, so `derive_base_seq` returns the pre-seal
                    // span; the resumed active then REUSES the orphan's sequences on the next append.
                }
                next_chirho.active_present_chirho = true;
                next_chirho.active_base_chirho = next_chirho.durable_span_chirho();
                next_chirho.active_count_chirho = 0;
                next_chirho.pending_chirho = false;
                Some(next_chirho)
            }
        }
    }

    fn properties(&self) -> Vec<Property<Self>> {
        if self.fold_on_recover_chirho {
            vec![
                Property::<Self>::always("rc1-rc2-no-seq-reuse-chirho", |_, state| {
                    state.no_seq_reuse_chirho()
                }),
                Property::<Self>::always("rc4-contiguous-partition-chirho", |_, state| {
                    state.contiguous_partition_chirho()
                }),
                Property::<Self>::always("active-opens-at-durable-span-chirho", |_, state| {
                    // The money invariant: an active file only exists fully-folded, opening exactly at
                    // the durable span — never coexisting with an un-manifested orphan.
                    !state.active_present_chirho
                        || (state.orphan_count_chirho.is_none()
                            && state.active_base_chirho == state.durable_span_chirho())
                }),
                Property::<Self>::sometimes("live-clean-rotated-reachable-chirho", |_, state| {
                    // Convergence + non-vacuity: a fully clean rotated state is reachable.
                    !state.durable_segments_chirho.is_empty()
                        && state.active_present_chirho
                        && state.orphan_count_chirho.is_none()
                }),
            ]
        } else {
            vec![Property::<Self>::sometimes(
                "reuse-reachable-without-fold-chirho",
                |_, state| {
                    // The mutation witness: skipping the intent-first fold makes a seq-reuse state
                    // REACHABLE — the exact RC.1 double-spend-class hole at the rotation boundary.
                    !state.no_seq_reuse_chirho()
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
    fn model_b_seq_continuity_holds_exhaustively_chirho() {
        // Up to 3 records: enough for append, rotate, refill, re-rotate, and a crash + recover at
        // every cut; every interleaving of the intent-first protocol checked in full.
        ModelBSeqChirho {
            max_records_chirho: 3,
            fold_on_recover_chirho: true,
        }
        .checker()
        .spawn_bfs()
        .join()
        .assert_properties();
    }

    #[test]
    fn model_b_seq_reuse_reachable_without_the_intent_first_fold_chirho() {
        // The mutation twin: recovery that resets the active WITHOUT folding the sealed orphan makes
        // a seq-reuse state reachable — proving the intent-first fold is load-bearing for RC.1.
        ModelBSeqChirho {
            max_records_chirho: 3,
            fold_on_recover_chirho: false,
        }
        .checker()
        .spawn_bfs()
        .join()
        .assert_properties();
    }
}
