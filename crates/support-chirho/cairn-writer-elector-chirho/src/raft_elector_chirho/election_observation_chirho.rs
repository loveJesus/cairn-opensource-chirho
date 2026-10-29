// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Coherent production observation of leadership, membership, and authenticated node identity.

use super::{RaftWriterElectorChirho, ELECTION_TICK_CHIRHO, NO_LEADER_RAFT_ID_CHIRHO};
use crate::elector_port_chirho::{LeadershipChirho, NodeIdChirho, WriterElectorChirho};
use anyhow::{anyhow, bail, Result};
use raft::{StateRole, Storage};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::Ordering;

const ELECTION_OBSERVATION_MAX_RETRIES_CHIRHO: usize = 4;

/// One coherent read of the live election state needed by production mirror composition.
///
/// The authenticated identity map is revalidated around the single raw-Raft read rather than held
/// under the raw-node mutex. That preserves the elector's existing no-nested-lock rule while proving
/// the returned leadership, membership, and identity population coexisted at one instant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RaftElectionObservationChirho {
    leadership_chirho: LeadershipChirho,
    authenticated_members_chirho: Vec<(u64, NodeIdChirho)>,
    voter_raft_ids_chirho: Vec<u64>,
    learner_raft_ids_chirho: Vec<u64>,
    applied_conf_index_chirho: u64,
    leader_lease_remaining_millis_chirho: Option<u64>,
}

impl RaftElectionObservationChirho {
    pub fn leadership_chirho(&self) -> &LeadershipChirho {
        &self.leadership_chirho
    }

    pub fn authenticated_members_chirho(&self) -> &[(u64, NodeIdChirho)] {
        &self.authenticated_members_chirho
    }

    pub fn voter_raft_ids_chirho(&self) -> &[u64] {
        &self.voter_raft_ids_chirho
    }

    pub fn learner_raft_ids_chirho(&self) -> &[u64] {
        &self.learner_raft_ids_chirho
    }

    pub fn applied_conf_index_chirho(&self) -> u64 {
        self.applied_conf_index_chirho
    }

    pub fn leader_lease_remaining_millis_chirho(&self) -> Option<u64> {
        self.leader_lease_remaining_millis_chirho
    }
}

impl RaftWriterElectorChirho {
    pub(super) fn monotonic_lease_valid_for_role_chirho(&self, is_leader_chirho: bool) -> bool {
        let Some(lease_chirho) = &self.monotonic_lease_chirho else {
            return false;
        };
        let now_chirho = lease_chirho.clock_chirho.now_millis_chirho();
        let since_chirho = self.leadership_since_ms_chirho.load(Ordering::Relaxed);
        let confirmed_chirho = self.leadership_confirmed_ms_chirho.load(Ordering::Relaxed);
        let warmup_elapsed_chirho = since_chirho != 0
            && now_chirho
                .checked_sub(since_chirho)
                .is_some_and(|elapsed_chirho| elapsed_chirho >= lease_chirho.warmup_millis_chirho);
        let confirmation_live_chirho = confirmed_chirho != 0
            && now_chirho
                .checked_sub(confirmed_chirho)
                .is_some_and(|elapsed_chirho| elapsed_chirho < lease_chirho.expiry_millis_chirho);
        is_leader_chirho && warmup_elapsed_chirho && confirmation_live_chirho
    }

    /// The leadership view for this elector's own consistency group.
    pub fn current_leadership_chirho(&self) -> LeadershipChirho {
        self.leadership_chirho(&self.group_chirho)
    }

    /// Resolve leadership, authenticated identities, voters/learners, and the applied configuration
    /// index as one coherent production observation without nesting the roster and raw-Raft locks.
    ///
    /// Convergence may replace the authenticated roster independently from Raft applying its matching
    /// configuration. A generation read around the raw snapshot proves the cloned roster did not move
    /// during that snapshot. Four bounded retries keep the hot path O(1); sustained churn refuses rather
    /// than fabricating a mixed view. Joint-consensus state also refuses, so routine membership changes
    /// deliberately halt mirror-gated tenant writes until their final configuration applies.
    pub fn current_election_observation_chirho(&self) -> Result<RaftElectionObservationChirho> {
        for _attempt_chirho in 0..ELECTION_OBSERVATION_MAX_RETRIES_CHIRHO {
            let generation_before_chirho = self
                .authenticated_roster_generation_chirho
                .load(Ordering::Acquire);
            let authenticated_members_chirho = self.authenticated_roster_snapshot_chirho();
            if generation_before_chirho
                != self
                    .authenticated_roster_generation_chirho
                    .load(Ordering::Acquire)
            {
                continue;
            }

            let raw_read_chirho =
                catch_unwind(AssertUnwindSafe(|| -> Result<_> {
                    let node_chirho = self.lock_node_chirho();
                    let status_chirho = node_chirho.status();
                    let leader_tick_count_chirho =
                        self.leader_tick_count_chirho.load(Ordering::Relaxed);
                    let state_chirho = node_chirho.raft.raft_log.store.initial_state().map_err(
                        |error_chirho| anyhow!("read coherent raft conf state: {error_chirho}"),
                    )?;
                    if !state_chirho.conf_state.voters_outgoing.is_empty()
                        || !state_chirho.conf_state.learners_next.is_empty()
                        || state_chirho.conf_state.auto_leave
                    {
                        bail!("coherent election observation refuses joint consensus");
                    }
                    let mut voter_raft_ids_chirho = state_chirho.conf_state.voters;
                    let mut learner_raft_ids_chirho = state_chirho.conf_state.learners;
                    voter_raft_ids_chirho.sort_unstable();
                    learner_raft_ids_chirho.sort_unstable();
                    let is_leader_chirho = status_chirho.ss.raft_state == StateRole::Leader;
                    let leader_raft_id_chirho = status_chirho.ss.leader_id;
                    let leadership_chirho = self.leadership_from_observed_raw_chirho(
                        is_leader_chirho,
                        leader_raft_id_chirho,
                        status_chirho.hs.term,
                        leader_tick_count_chirho,
                        &authenticated_members_chirho,
                    );
                    let leader_lease_remaining_millis_chirho =
                        self.lease_remaining_for_observed_leadership_chirho(&leadership_chirho);
                    Ok((
                        leadership_chirho,
                        leader_raft_id_chirho,
                        voter_raft_ids_chirho,
                        learner_raft_ids_chirho,
                        node_chirho
                            .raft
                            .raft_log
                            .store
                            .current_applied_conf_index_chirho(),
                        leader_lease_remaining_millis_chirho,
                    ))
                }));
            let (
                leadership_chirho,
                leader_raft_id_chirho,
                voter_raft_ids_chirho,
                learner_raft_ids_chirho,
                applied_conf_index_chirho,
                leader_lease_remaining_millis_chirho,
            ) = raw_read_chirho
                .map_err(|_| anyhow!("coherent election observation panicked"))??;

            if generation_before_chirho
                != self
                    .authenticated_roster_generation_chirho
                    .load(Ordering::Acquire)
            {
                continue;
            }
            if leader_raft_id_chirho != NO_LEADER_RAFT_ID_CHIRHO
                && !authenticated_members_chirho
                    .iter()
                    .any(|(raft_id_chirho, _)| *raft_id_chirho == leader_raft_id_chirho)
            {
                bail!("coherent election observation leader has no authenticated identity");
            }
            return Ok(RaftElectionObservationChirho {
                leadership_chirho,
                authenticated_members_chirho,
                voter_raft_ids_chirho,
                learner_raft_ids_chirho,
                applied_conf_index_chirho,
                leader_lease_remaining_millis_chirho,
            });
        }
        bail!("authenticated roster changed throughout coherent election observation")
    }

    /// This node's remaining lease, for the group it governs.
    pub fn current_lease_remaining_millis_chirho(&self) -> Option<u64> {
        self.lease_remaining_millis_chirho(&self.group_chirho.clone())
    }

    fn lease_remaining_for_observed_leadership_chirho(
        &self,
        leadership_chirho: &LeadershipChirho,
    ) -> Option<u64> {
        if !leadership_chirho.is_leader_chirho || !leadership_chirho.lease_valid_chirho {
            return None;
        }
        let lease_chirho = self.monotonic_lease_chirho.as_ref()?;
        let now_chirho = lease_chirho.clock_chirho.now_millis_chirho();
        let confirmed_chirho = self.leadership_confirmed_ms_chirho.load(Ordering::Relaxed);
        let elapsed_chirho = now_chirho.checked_sub(confirmed_chirho)?;
        lease_chirho
            .expiry_millis_chirho
            .checked_sub(elapsed_chirho)
            .filter(|remaining_chirho| *remaining_chirho > 0)
    }

    fn leadership_from_observed_raw_chirho(
        &self,
        is_leader_chirho: bool,
        leader_raft_id_chirho: u64,
        term_chirho: u64,
        leader_tick_count_chirho: u64,
        authenticated_members_chirho: &[(u64, NodeIdChirho)],
    ) -> LeadershipChirho {
        let leader_id_chirho = if leader_raft_id_chirho == NO_LEADER_RAFT_ID_CHIRHO {
            None
        } else {
            authenticated_members_chirho
                .iter()
                .find(|(raft_id_chirho, _)| *raft_id_chirho == leader_raft_id_chirho)
                .map(|(_, node_chirho)| node_chirho.clone())
        };
        let lease_valid_chirho = if self.monotonic_lease_chirho.is_some() {
            self.monotonic_lease_valid_for_role_chirho(is_leader_chirho)
        } else if self.lease_warmup_enabled_chirho {
            is_leader_chirho && leader_tick_count_chirho >= ELECTION_TICK_CHIRHO as u64
        } else {
            is_leader_chirho
        };
        LeadershipChirho {
            is_leader_chirho,
            leader_id_chirho,
            term_chirho,
            lease_valid_chirho,
        }
    }
}
