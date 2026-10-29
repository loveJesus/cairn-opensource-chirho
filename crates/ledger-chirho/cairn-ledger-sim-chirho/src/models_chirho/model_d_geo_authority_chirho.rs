// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Model D geo money-authority composition proof.
//!
//! Workflow contract: `spec-chirho/workflows-chirho/distributed-ha-chirho/`
//! `cf8-a6-money-election-design-chirho.md` section 4.
//!
//! A composite epoch is `(geo_term << 32) | local_grant_seq`. Before the first geo
//! election, only the home authority operates. Activation records and clears the
//! pre-geo epoch floor before moving authority into the geo-active phase. The D1
//! sink then admits only the currently granted epoch, and every accepted move to a
//! strictly newer composite epoch anchors the exact prior identity.
//!
//! Election safety itself remains an assumed precondition of this composition
//! model. Stale refusal evidence is bounded and describes an unappended candidate;
//! it is not a durable fork record or an effect (and therefore is not GD7).
//! Liveness under partition is deliberately not claimed: a majority-less authority
//! group mints nothing. Leases may bound stale work, but no timer is trusted for
//! money safety; the append fence remains decisive.
//!
//! State transitions are O(1) under the fixed arrays and configured bounds. Action
//! enumeration is O(clusters * regions), property evaluation is
//! O(clusters * max_records), and exhaustive BFS is exponential in the configured
//! bounds. Do not grow these bounds casually.

use stateright::{Model, Property};

const NUM_CLUSTERS_CHIRHO: usize = 2;
const NUM_REGIONS_CHIRHO: usize = 2;
const HOME_REGION_CHIRHO: usize = 0;

fn checked_pack_epoch_chirho(geo_term_chirho: u64, local_seq_chirho: u64) -> Option<u64> {
    if geo_term_chirho > u32::MAX as u64 || local_seq_chirho > u32::MAX as u64 {
        return None;
    }
    Some((geo_term_chirho << 32) | local_seq_chirho)
}

fn geo_term_of_chirho(epoch_chirho: u64) -> u64 {
    epoch_chirho >> 32
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum AuthorityPhaseChirho {
    PreGeoChirho,
    GeoActiveChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct IdentityChirho {
    epoch_chirho: u64,
    seq_chirho: u64,
    digest_chirho: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum TransferChirho {
    AtSourceChirho,
    InSettlementChirho,
    AtDestChirho,
    InLimboChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PendingMintChirho {
    identity_chirho: IdentityChirho,
    region_chirho: usize,
    held_at_mint_chirho: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct RecordDChirho {
    identity_chirho: IdentityChirho,
    region_chirho: usize,
    anchor_chirho: Option<IdentityChirho>,
    granted_epoch_at_append_chirho: u64,
    held_at_mint_chirho: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct GeoActivationChirho {
    first_geo_epoch_chirho: u64,
    max_pre_geo_epoch_chirho: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct StaleRefusalEvidenceChirho {
    cluster_chirho: usize,
    candidate_chirho: IdentityChirho,
    authoritative_tail_chirho: IdentityChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum GrantKindChirho {
    LocalChirho { cluster_chirho: usize },
    ElectionChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct GrantTransitionChirho {
    kind_chirho: GrantKindChirho,
    before_phase_chirho: AuthorityPhaseChirho,
    before_geo_term_chirho: u64,
    before_holder_chirho: usize,
    before_seqs_chirho: [u64; NUM_CLUSTERS_CHIRHO],
}

/// Bounded composition state for the pre-geo -> geo-active authority cutover.
///
/// `activation_chirho` is immutable cutover evidence. `stale_refusal_chirho` describes only an
/// unappended candidate rejected by the shared sink; it is not durable losing-fork evidence and
/// must not be mistaken for the separate GD7 reconciliation proof.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StateDChirho {
    phase_chirho: AuthorityPhaseChirho,
    geo_term_chirho: u64,
    holder_chirho: usize,
    local_seq_chirho: [u64; NUM_CLUSTERS_CHIRHO],
    journals_chirho: [Vec<RecordDChirho>; NUM_CLUSTERS_CHIRHO],
    pending_mint_chirho: [[Option<PendingMintChirho>; NUM_CLUSTERS_CHIRHO]; NUM_REGIONS_CHIRHO],
    transfer_chirho: TransferChirho,
    activation_chirho: Option<GeoActivationChirho>,
    stale_refusal_chirho: Option<StaleRefusalEvidenceChirho>,
    last_grant_transition_chirho: Option<GrantTransitionChirho>,
    saw_crash_regrant_chirho: bool,
    saw_non_home_holder_chirho: bool,
}

/// Environment actions explored by the checker. Election candidates normally advance the term;
/// `stale_activation_candidate_chirho` below adds an adversarial same-term cutover candidate so the
/// floor validator is exercised independently of the candidate generator.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ActionDChirho {
    MintChirho {
        cluster_chirho: usize,
        region_chirho: usize,
    },
    LocalGrantChirho {
        cluster_chirho: usize,
    },
    CrashRecoverChirho {
        cluster_chirho: usize,
    },
    ElectionChirho {
        to_region_chirho: usize,
    },
    AppendChirho {
        cluster_chirho: usize,
        region_chirho: usize,
    },
}

/// Protocol laws default TRUE. A mutation test disables one law at a time; non-law configuration
/// knobs alter only bounded exploration. In particular, `stale_activation_candidate_chirho` is an
/// adversarial-input scenario, not permission to accept that candidate.
pub struct ModelDChirho {
    pub max_geo_term_chirho: u64,
    pub local_seq_max_chirho: u64,
    pub max_records_chirho: usize,
    pub mint_legit_law_chirho: bool,
    pub sink_fence_law_chirho: bool,
    pub crossing_anchor_law_chirho: bool,
    pub local_regrant_anchor_law_chirho: bool,
    pub exact_anchor_law_chirho: bool,
    pub conserve_on_handoff_law_chirho: bool,
    pub election_reset_law_chirho: bool,
    pub wrap_refusal_law_chirho: bool,
    pub term_floor_law_chirho: bool,
    pub failback_term_increment_law_chirho: bool,
    pub retire_rejected_pending_law_chirho: bool,
    pub stale_activation_candidate_chirho: bool,
    pub money_enabled_chirho: bool,
    pub transition_tracking_enabled_chirho: bool,
    pub sink_enabled_chirho: bool,
    pub active_clusters_chirho: usize,
}

impl ModelDChirho {
    fn current_e_chirho(state_chirho: &StateDChirho, cluster_chirho: usize) -> Option<u64> {
        checked_pack_epoch_chirho(
            state_chirho.geo_term_chirho,
            state_chirho.local_seq_chirho[cluster_chirho],
        )
    }

    fn tail_chirho(state_chirho: &StateDChirho, cluster_chirho: usize) -> Option<RecordDChirho> {
        state_chirho.journals_chirho[cluster_chirho].last().copied()
    }

    fn next_seq_digest_chirho(tail_chirho: Option<RecordDChirho>, epoch_chirho: u64) -> (u64, u64) {
        match tail_chirho {
            Some(record_chirho) => {
                let seq_chirho = if record_chirho.identity_chirho.epoch_chirho == epoch_chirho {
                    record_chirho.identity_chirho.seq_chirho + 1
                } else {
                    0
                };
                (seq_chirho, record_chirho.identity_chirho.digest_chirho + 1)
            }
            None => (0, 0),
        }
    }

    fn max_pre_geo_epoch_chirho(&self, state_chirho: &StateDChirho) -> Option<u64> {
        let mut maximum_chirho = 0;
        for cluster_chirho in 0..NUM_CLUSTERS_CHIRHO {
            maximum_chirho =
                maximum_chirho.max(Self::current_e_chirho(state_chirho, cluster_chirho)?);
            for record_chirho in &state_chirho.journals_chirho[cluster_chirho] {
                maximum_chirho = maximum_chirho.max(record_chirho.identity_chirho.epoch_chirho);
            }
            for region_chirho in 0..NUM_REGIONS_CHIRHO {
                if let Some(pending_chirho) =
                    state_chirho.pending_mint_chirho[region_chirho][cluster_chirho]
                {
                    maximum_chirho =
                        maximum_chirho.max(pending_chirho.identity_chirho.epoch_chirho);
                }
            }
        }
        Some(maximum_chirho)
    }

    fn admit_chirho(
        &self,
        state_chirho: &StateDChirho,
        cluster_chirho: usize,
        pending_chirho: &PendingMintChirho,
    ) -> Option<RecordDChirho> {
        // The one shared append decision: legitimacy, exact current grant, chain identity, and
        // continuity anchors are checked here for both current and deposed-region candidates.
        if state_chirho.journals_chirho[cluster_chirho].len() >= self.max_records_chirho {
            return None;
        }
        let granted_epoch_chirho = Self::current_e_chirho(state_chirho, cluster_chirho)?;
        let tail_chirho = Self::tail_chirho(state_chirho, cluster_chirho);
        let candidate_chirho = pending_chirho.identity_chirho;

        if self.mint_legit_law_chirho && !pending_chirho.held_at_mint_chirho {
            return None;
        }

        if self.sink_fence_law_chirho {
            if candidate_chirho.epoch_chirho != granted_epoch_chirho {
                return None;
            }
            let (expected_seq_chirho, expected_digest_chirho) =
                Self::next_seq_digest_chirho(tail_chirho, candidate_chirho.epoch_chirho);
            if candidate_chirho.seq_chirho != expected_seq_chirho
                || candidate_chirho.digest_chirho != expected_digest_chirho
            {
                return None;
            }
            if let Some(prior_chirho) = tail_chirho {
                if candidate_chirho.epoch_chirho < prior_chirho.identity_chirho.epoch_chirho {
                    return None;
                }
                if candidate_chirho.epoch_chirho == prior_chirho.identity_chirho.epoch_chirho
                    && pending_chirho.region_chirho != prior_chirho.region_chirho
                {
                    return None;
                }
            }
        }

        let anchor_chirho = match tail_chirho {
            Some(prior_chirho)
                if candidate_chirho.epoch_chirho > prior_chirho.identity_chirho.epoch_chirho =>
            {
                let local_regrant_chirho = geo_term_of_chirho(candidate_chirho.epoch_chirho)
                    == geo_term_of_chirho(prior_chirho.identity_chirho.epoch_chirho);
                let anchor_required_chirho = if local_regrant_chirho {
                    self.local_regrant_anchor_law_chirho
                } else {
                    self.crossing_anchor_law_chirho
                };
                if !anchor_required_chirho {
                    None
                } else if self.exact_anchor_law_chirho {
                    Some(prior_chirho.identity_chirho)
                } else {
                    Some(state_chirho.journals_chirho[cluster_chirho][0].identity_chirho)
                }
            }
            _ => None,
        };

        Some(RecordDChirho {
            identity_chirho: candidate_chirho,
            region_chirho: pending_chirho.region_chirho,
            anchor_chirho,
            granted_epoch_at_append_chirho: granted_epoch_chirho,
            held_at_mint_chirho: pending_chirho.held_at_mint_chirho,
        })
    }

    fn last_transition_lawful_chirho(&self, state_chirho: &StateDChirho) -> bool {
        let transition_chirho = match state_chirho.last_grant_transition_chirho {
            Some(transition_chirho) => transition_chirho,
            None => return true,
        };
        match transition_chirho.kind_chirho {
            GrantKindChirho::LocalChirho { cluster_chirho } => {
                state_chirho.phase_chirho == transition_chirho.before_phase_chirho
                    && state_chirho.geo_term_chirho == transition_chirho.before_geo_term_chirho
                    && transition_chirho.before_seqs_chirho[cluster_chirho]
                        < self.local_seq_max_chirho
                    && state_chirho.local_seq_chirho[cluster_chirho]
                        == transition_chirho.before_seqs_chirho[cluster_chirho] + 1
                    && (0..NUM_CLUSTERS_CHIRHO).all(|other_chirho| {
                        other_chirho == cluster_chirho
                            || state_chirho.local_seq_chirho[other_chirho]
                                == transition_chirho.before_seqs_chirho[other_chirho]
                    })
            }
            GrantKindChirho::ElectionChirho => {
                state_chirho.geo_term_chirho == transition_chirho.before_geo_term_chirho + 1
                    && state_chirho
                        .local_seq_chirho
                        .iter()
                        .all(|seq_chirho| *seq_chirho == 0)
            }
        }
    }

    fn failback_transition_lawful_chirho(state_chirho: &StateDChirho) -> bool {
        let transition_chirho = match state_chirho.last_grant_transition_chirho {
            Some(transition_chirho) => transition_chirho,
            None => return true,
        };
        let actual_failback_chirho = transition_chirho.kind_chirho
            == GrantKindChirho::ElectionChirho
            && transition_chirho.before_phase_chirho == AuthorityPhaseChirho::GeoActiveChirho
            && transition_chirho.before_holder_chirho != HOME_REGION_CHIRHO
            && state_chirho.holder_chirho == HOME_REGION_CHIRHO;
        !actual_failback_chirho
            || state_chirho.geo_term_chirho == transition_chirho.before_geo_term_chirho + 1
    }

    fn joined_spine_chirho(state_chirho: &StateDChirho) -> bool {
        let activation_chirho = match state_chirho.activation_chirho {
            Some(activation_chirho) => activation_chirho,
            None => return false,
        };
        let evidence_chirho = match state_chirho.stale_refusal_chirho {
            Some(evidence_chirho) => evidence_chirho,
            None => return false,
        };
        let journal_chirho = &state_chirho.journals_chirho[evidence_chirho.cluster_chirho];
        if journal_chirho.len() != 4 {
            return false;
        }
        let seed_chirho = journal_chirho[0];
        let local_chirho = journal_chirho[1];
        let crossing_chirho = journal_chirho[2];
        let failback_chirho = journal_chirho[3];
        let expected_stale_chirho = IdentityChirho {
            epoch_chirho: local_chirho.identity_chirho.epoch_chirho,
            seq_chirho: local_chirho.identity_chirho.seq_chirho + 1,
            digest_chirho: local_chirho.identity_chirho.digest_chirho + 1,
        };

        seed_chirho.region_chirho == HOME_REGION_CHIRHO
            && local_chirho.region_chirho == HOME_REGION_CHIRHO
            && local_chirho.identity_chirho.epoch_chirho > seed_chirho.identity_chirho.epoch_chirho
            && geo_term_of_chirho(local_chirho.identity_chirho.epoch_chirho)
                == geo_term_of_chirho(seed_chirho.identity_chirho.epoch_chirho)
            && local_chirho.anchor_chirho == Some(seed_chirho.identity_chirho)
            && activation_chirho.max_pre_geo_epoch_chirho
                >= local_chirho.identity_chirho.epoch_chirho
            && crossing_chirho.identity_chirho.epoch_chirho
                == activation_chirho.first_geo_epoch_chirho
            && crossing_chirho.region_chirho != HOME_REGION_CHIRHO
            && crossing_chirho.anchor_chirho == Some(local_chirho.identity_chirho)
            && evidence_chirho.candidate_chirho == expected_stale_chirho
            && evidence_chirho.authoritative_tail_chirho == crossing_chirho.identity_chirho
            && state_chirho.pending_mint_chirho[HOME_REGION_CHIRHO][evidence_chirho.cluster_chirho]
                .is_none()
            && failback_chirho.region_chirho == HOME_REGION_CHIRHO
            && geo_term_of_chirho(failback_chirho.identity_chirho.epoch_chirho)
                == geo_term_of_chirho(crossing_chirho.identity_chirho.epoch_chirho) + 1
            && failback_chirho.anchor_chirho == Some(crossing_chirho.identity_chirho)
    }

    fn advance_transfer_chirho(&self, transfer_chirho: TransferChirho) -> TransferChirho {
        if !self.money_enabled_chirho {
            return transfer_chirho;
        }
        match transfer_chirho {
            TransferChirho::AtSourceChirho => TransferChirho::InSettlementChirho,
            TransferChirho::InSettlementChirho => TransferChirho::AtDestChirho,
            TransferChirho::AtDestChirho => TransferChirho::AtDestChirho,
            TransferChirho::InLimboChirho => TransferChirho::InLimboChirho,
        }
    }

    fn record_transition_chirho(
        &self,
        next_chirho: &mut StateDChirho,
        kind_chirho: GrantKindChirho,
        last_chirho: &StateDChirho,
    ) {
        if self.transition_tracking_enabled_chirho {
            next_chirho.last_grant_transition_chirho = Some(GrantTransitionChirho {
                kind_chirho,
                before_phase_chirho: last_chirho.phase_chirho,
                before_geo_term_chirho: last_chirho.geo_term_chirho,
                before_holder_chirho: last_chirho.holder_chirho,
                before_seqs_chirho: last_chirho.local_seq_chirho,
            });
        }
    }

    fn local_grant_chirho(
        &self,
        last_chirho: &StateDChirho,
        cluster_chirho: usize,
        is_crash_chirho: bool,
    ) -> Option<StateDChirho> {
        let saturated_chirho = last_chirho.local_seq_chirho[cluster_chirho]
            >= self.local_seq_max_chirho
            || last_chirho.local_seq_chirho[cluster_chirho] >= u32::MAX as u64;
        let mut next_chirho = last_chirho.clone();
        if saturated_chirho {
            if self.wrap_refusal_law_chirho {
                return None;
            }
            next_chirho.local_seq_chirho[cluster_chirho] = 0;
        } else {
            next_chirho.local_seq_chirho[cluster_chirho] += 1;
        }
        Self::current_e_chirho(&next_chirho, cluster_chirho)?;
        self.record_transition_chirho(
            &mut next_chirho,
            GrantKindChirho::LocalChirho { cluster_chirho },
            last_chirho,
        );
        if is_crash_chirho {
            next_chirho.saw_crash_regrant_chirho = true;
        }
        Some(next_chirho)
    }

    fn election_chirho(
        &self,
        last_chirho: &StateDChirho,
        to_region_chirho: usize,
    ) -> Option<StateDChirho> {
        if last_chirho.geo_term_chirho >= self.max_geo_term_chirho {
            return None;
        }
        let activating_chirho = last_chirho.phase_chirho == AuthorityPhaseChirho::PreGeoChirho;
        let same_term_failback_chirho = !activating_chirho
            && last_chirho.holder_chirho != HOME_REGION_CHIRHO
            && to_region_chirho == HOME_REGION_CHIRHO
            && !self.failback_term_increment_law_chirho;
        let stale_activation_candidate_chirho =
            activating_chirho && self.stale_activation_candidate_chirho;
        let next_term_chirho = if stale_activation_candidate_chirho || same_term_failback_chirho {
            last_chirho.geo_term_chirho
        } else {
            last_chirho.geo_term_chirho.checked_add(1)?
        };
        let first_epoch_chirho = checked_pack_epoch_chirho(next_term_chirho, 0)?;
        let mut next_chirho = last_chirho.clone();

        if activating_chirho {
            let max_pre_geo_epoch_chirho = self.max_pre_geo_epoch_chirho(last_chirho)?;
            if self.term_floor_law_chirho && first_epoch_chirho <= max_pre_geo_epoch_chirho {
                return None;
            }
            next_chirho.phase_chirho = AuthorityPhaseChirho::GeoActiveChirho;
            next_chirho.activation_chirho = Some(GeoActivationChirho {
                first_geo_epoch_chirho: first_epoch_chirho,
                max_pre_geo_epoch_chirho,
            });
        }
        next_chirho.geo_term_chirho = next_term_chirho;
        next_chirho.holder_chirho = to_region_chirho;
        if self.election_reset_law_chirho {
            next_chirho.local_seq_chirho = [0; NUM_CLUSTERS_CHIRHO];
        }
        self.record_transition_chirho(
            &mut next_chirho,
            GrantKindChirho::ElectionChirho,
            last_chirho,
        );
        if to_region_chirho != HOME_REGION_CHIRHO {
            next_chirho.saw_non_home_holder_chirho = true;
        }
        if self.money_enabled_chirho
            && !self.conserve_on_handoff_law_chirho
            && next_chirho.transfer_chirho == TransferChirho::InSettlementChirho
        {
            next_chirho.transfer_chirho = TransferChirho::InLimboChirho;
        }
        Some(next_chirho)
    }
}

impl Model for ModelDChirho {
    type State = StateDChirho;
    type Action = ActionDChirho;

    fn init_states(&self) -> Vec<Self::State> {
        vec![StateDChirho {
            phase_chirho: AuthorityPhaseChirho::PreGeoChirho,
            geo_term_chirho: 0,
            holder_chirho: HOME_REGION_CHIRHO,
            local_seq_chirho: [0; NUM_CLUSTERS_CHIRHO],
            journals_chirho: [Vec::new(), Vec::new()],
            pending_mint_chirho: [[None; NUM_CLUSTERS_CHIRHO]; NUM_REGIONS_CHIRHO],
            transfer_chirho: TransferChirho::AtSourceChirho,
            activation_chirho: None,
            stale_refusal_chirho: None,
            last_grant_transition_chirho: None,
            saw_crash_regrant_chirho: false,
            saw_non_home_holder_chirho: false,
        }]
    }

    fn actions(&self, state_chirho: &Self::State, actions_chirho: &mut Vec<Self::Action>) {
        // O(clusters * regions) under the fixed arrays and configured active-cluster bound.
        for cluster_chirho in 0..self.active_clusters_chirho.min(NUM_CLUSTERS_CHIRHO) {
            if self.sink_enabled_chirho {
                for region_chirho in 0..NUM_REGIONS_CHIRHO {
                    if state_chirho.pending_mint_chirho[region_chirho][cluster_chirho].is_some() {
                        actions_chirho.push(ActionDChirho::AppendChirho {
                            cluster_chirho,
                            region_chirho,
                        });
                    } else {
                        let pre_geo_home_chirho = state_chirho.phase_chirho
                            == AuthorityPhaseChirho::PreGeoChirho
                            && region_chirho == HOME_REGION_CHIRHO;
                        let geo_holder_chirho = state_chirho.phase_chirho
                            == AuthorityPhaseChirho::GeoActiveChirho
                            && (region_chirho == state_chirho.holder_chirho
                                || !self.mint_legit_law_chirho);
                        if pre_geo_home_chirho || geo_holder_chirho {
                            actions_chirho.push(ActionDChirho::MintChirho {
                                cluster_chirho,
                                region_chirho,
                            });
                        }
                    }
                }
            }
            actions_chirho.push(ActionDChirho::LocalGrantChirho { cluster_chirho });
            actions_chirho.push(ActionDChirho::CrashRecoverChirho { cluster_chirho });
        }
        if state_chirho.geo_term_chirho < self.max_geo_term_chirho {
            for to_region_chirho in 0..NUM_REGIONS_CHIRHO {
                actions_chirho.push(ActionDChirho::ElectionChirho { to_region_chirho });
            }
        }
    }

    fn next_state(
        &self,
        last_chirho: &Self::State,
        action_chirho: Self::Action,
    ) -> Option<Self::State> {
        match action_chirho {
            ActionDChirho::MintChirho {
                cluster_chirho,
                region_chirho,
            } => {
                if last_chirho.pending_mint_chirho[region_chirho][cluster_chirho].is_some() {
                    return None;
                }
                if last_chirho.phase_chirho == AuthorityPhaseChirho::PreGeoChirho
                    && region_chirho != HOME_REGION_CHIRHO
                {
                    return None;
                }
                let epoch_chirho = Self::current_e_chirho(last_chirho, cluster_chirho)?;
                let (seq_chirho, digest_chirho) = Self::next_seq_digest_chirho(
                    Self::tail_chirho(last_chirho, cluster_chirho),
                    epoch_chirho,
                );
                let held_at_mint_chirho = match last_chirho.phase_chirho {
                    AuthorityPhaseChirho::PreGeoChirho => region_chirho == HOME_REGION_CHIRHO,
                    AuthorityPhaseChirho::GeoActiveChirho => {
                        region_chirho == last_chirho.holder_chirho
                    }
                };
                let mut next_chirho = last_chirho.clone();
                next_chirho.pending_mint_chirho[region_chirho][cluster_chirho] =
                    Some(PendingMintChirho {
                        identity_chirho: IdentityChirho {
                            epoch_chirho,
                            seq_chirho,
                            digest_chirho,
                        },
                        region_chirho,
                        held_at_mint_chirho,
                    });
                Some(next_chirho)
            }
            ActionDChirho::LocalGrantChirho { cluster_chirho } => {
                self.local_grant_chirho(last_chirho, cluster_chirho, false)
            }
            ActionDChirho::CrashRecoverChirho { cluster_chirho } => {
                self.local_grant_chirho(last_chirho, cluster_chirho, true)
            }
            ActionDChirho::ElectionChirho { to_region_chirho } => {
                self.election_chirho(last_chirho, to_region_chirho)
            }
            ActionDChirho::AppendChirho {
                cluster_chirho,
                region_chirho,
            } => {
                let pending_chirho =
                    last_chirho.pending_mint_chirho[region_chirho][cluster_chirho]?;
                if let Some(record_chirho) =
                    self.admit_chirho(last_chirho, cluster_chirho, &pending_chirho)
                {
                    let mut next_chirho = last_chirho.clone();
                    next_chirho.journals_chirho[cluster_chirho].push(record_chirho);
                    next_chirho.pending_mint_chirho[region_chirho][cluster_chirho] = None;
                    next_chirho.transfer_chirho =
                        self.advance_transfer_chirho(next_chirho.transfer_chirho);
                    return Some(next_chirho);
                }

                let authoritative_tail_chirho = Self::tail_chirho(last_chirho, cluster_chirho)?;
                let recognized_stale_chirho = pending_chirho.held_at_mint_chirho
                    && pending_chirho.identity_chirho.epoch_chirho
                        < authoritative_tail_chirho.identity_chirho.epoch_chirho
                    && pending_chirho.region_chirho != authoritative_tail_chirho.region_chirho;
                if !recognized_stale_chirho {
                    return None;
                }
                let evidence_chirho = StaleRefusalEvidenceChirho {
                    cluster_chirho,
                    candidate_chirho: pending_chirho.identity_chirho,
                    authoritative_tail_chirho: authoritative_tail_chirho.identity_chirho,
                };
                if last_chirho.stale_refusal_chirho == Some(evidence_chirho)
                    && !self.retire_rejected_pending_law_chirho
                {
                    return None;
                }
                let mut next_chirho = last_chirho.clone();
                next_chirho.stale_refusal_chirho = Some(evidence_chirho);
                if self.retire_rejected_pending_law_chirho {
                    next_chirho.pending_mint_chirho[region_chirho][cluster_chirho] = None;
                }
                Some(next_chirho)
            }
        }
    }

    fn properties(&self) -> Vec<Property<Self>> {
        // O(clusters * max_records); no property traverses an unbounded event history.
        vec![
            Property::<Self>::always("md1-mint-under-held-term-chirho", |_, state_chirho| {
                state_chirho.journals_chirho.iter().all(|journal_chirho| {
                    journal_chirho
                        .iter()
                        .all(|record_chirho| record_chirho.held_at_mint_chirho)
                })
            }),
            Property::<Self>::always("md2-sink-epoch-eq-granted-chirho", |_, state_chirho| {
                state_chirho.journals_chirho.iter().all(|journal_chirho| {
                    let exact_grant_chirho = journal_chirho.iter().all(|record_chirho| {
                        record_chirho.identity_chirho.epoch_chirho
                            == record_chirho.granted_epoch_at_append_chirho
                    });
                    let nondecreasing_chirho = journal_chirho.windows(2).all(|pair_chirho| {
                        pair_chirho[0].identity_chirho.epoch_chirho
                            <= pair_chirho[1].identity_chirho.epoch_chirho
                    });
                    let one_region_chirho = journal_chirho.windows(2).all(|pair_chirho| {
                        pair_chirho[0].identity_chirho.epoch_chirho
                            != pair_chirho[1].identity_chirho.epoch_chirho
                            || pair_chirho[0].region_chirho == pair_chirho[1].region_chirho
                    });
                    exact_grant_chirho && nondecreasing_chirho && one_region_chirho
                })
            }),
            Property::<Self>::always(
                "md2-post-crossing-deposed-replay-chirho",
                |_, state_chirho| {
                    state_chirho.journals_chirho.iter().all(|journal_chirho| {
                        journal_chirho.windows(2).all(|pair_chirho| {
                            let prior_chirho = pair_chirho[0];
                            let replay_chirho = pair_chirho[1];
                            !(prior_chirho.region_chirho != replay_chirho.region_chirho
                                && replay_chirho.held_at_mint_chirho
                                && replay_chirho.identity_chirho.epoch_chirho
                                    < prior_chirho.identity_chirho.epoch_chirho
                                && replay_chirho.identity_chirho.epoch_chirho
                                    != replay_chirho.granted_epoch_at_append_chirho)
                        })
                    })
                },
            ),
            Property::<Self>::always("md3-handoff-conserves-chirho", |_, state_chirho| {
                state_chirho.transfer_chirho != TransferChirho::InLimboChirho
            }),
            Property::<Self>::always("md4-failback-term-increments-chirho", |_, state_chirho| {
                Self::failback_transition_lawful_chirho(state_chirho)
            }),
            Property::<Self>::always("md5-anchor-continuity-chirho", |_, state_chirho| {
                state_chirho.journals_chirho.iter().all(|journal_chirho| {
                    journal_chirho.windows(2).all(|pair_chirho| {
                        let prior_chirho = pair_chirho[0];
                        let current_chirho = pair_chirho[1];
                        if current_chirho.identity_chirho.epoch_chirho
                            > prior_chirho.identity_chirho.epoch_chirho
                        {
                            current_chirho.anchor_chirho == Some(prior_chirho.identity_chirho)
                        } else if current_chirho.identity_chirho.epoch_chirho
                            == prior_chirho.identity_chirho.epoch_chirho
                        {
                            current_chirho.anchor_chirho.is_none()
                        } else {
                            true
                        }
                    })
                })
            }),
            Property::<Self>::always("gd5-first-geo-term-floor-chirho", |_, state_chirho| {
                state_chirho
                    .activation_chirho
                    .is_none_or(|activation_chirho| {
                        activation_chirho.first_geo_epoch_chirho
                            > activation_chirho.max_pre_geo_epoch_chirho
                    })
            }),
            Property::<Self>::sometimes(
                "md6-cross-region-handoff-reachable-chirho",
                |_, state_chirho| {
                    state_chirho.journals_chirho.iter().any(|journal_chirho| {
                        journal_chirho.windows(2).any(|pair_chirho| {
                            pair_chirho[1].identity_chirho.epoch_chirho
                                > pair_chirho[0].identity_chirho.epoch_chirho
                                && pair_chirho[1].region_chirho != pair_chirho[0].region_chirho
                        })
                    })
                },
            ),
            Property::<Self>::sometimes(
                "md6-rejected-stale-reachable-chirho",
                |_, state_chirho| state_chirho.stale_refusal_chirho.is_some(),
            ),
            Property::<Self>::sometimes("md6-crash-regrant-reachable-chirho", |_, state_chirho| {
                state_chirho.saw_crash_regrant_chirho
            }),
            Property::<Self>::sometimes("md6-failback-reachable-chirho", |_, state_chirho| {
                state_chirho.phase_chirho == AuthorityPhaseChirho::GeoActiveChirho
                    && state_chirho.holder_chirho == HOME_REGION_CHIRHO
                    && state_chirho.saw_non_home_holder_chirho
                    && state_chirho.geo_term_chirho >= 2
            }),
            Property::<Self>::always(
                "md7-transition-contract-chirho",
                |model_chirho, state_chirho| {
                    model_chirho.last_transition_lawful_chirho(state_chirho)
                },
            ),
            Property::<Self>::sometimes(
                "f5-multi-record-lease-reachable-chirho",
                |_, state_chirho| {
                    state_chirho.journals_chirho.iter().any(|journal_chirho| {
                        journal_chirho.windows(2).any(|pair_chirho| {
                            pair_chirho[0].identity_chirho.epoch_chirho
                                == pair_chirho[1].identity_chirho.epoch_chirho
                        })
                    })
                },
            ),
            Property::<Self>::sometimes(
                "gd6-cutover-handoff-stale-failback-spine-chirho",
                |_, state_chirho| Self::joined_spine_chirho(state_chirho),
            ),
        ]
    }
}

#[cfg(test)]
#[path = "model_d_geo_authority_tests_chirho.rs"]
mod tests_chirho;
