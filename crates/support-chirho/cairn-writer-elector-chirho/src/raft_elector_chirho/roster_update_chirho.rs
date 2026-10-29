// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! Replacing the authenticated roster under the same admission seal as every Raft transition.

use super::RaftWriterElectorChirho;
use crate::elector_port_chirho::NodeIdChirho;
use anyhow::{anyhow, bail, Result};
use std::collections::BTreeSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::Ordering;

impl RaftWriterElectorChirho {
    /// Live-update the authenticated peer set (A1.3 slice 1): atomically replace WHO this node
    /// authenticates inbound raft messages against, so the convergence driver can add/remove a peer on a
    /// RUNNING elector with no restart. The elector OWNS this invariant — a driver never reaches into the
    /// set, it requests a validated change here, and this method does NOT trust the driver: it enforces
    /// the full raft-id ↔ node-identity BIJECTION. Refuses a duplicate raft id (an id must authenticate
    /// exactly one key) AND a duplicate node identity (one key must not authenticate as two raft ids —
    /// else a single node could vote as two members and manufacture a self-majority), plus a set that
    /// drops or remaps the LOCAL node (a node must always authenticate as itself). The whole set swaps
    /// atomically under the write lock, so a concurrent reader sees either the old set or the new one,
    /// never a torn mix. This mints nothing and moves no head — it governs only message authentication, so
    /// it stays inside the shadow (non-authoritative) envelope.
    ///
    /// The swap is SEALED like a Raft transition (A6-c; gpt #29847, claude2 #29848, Agy #29851, gpt
    /// #29852). Pure validation refuses first and touches nothing. Then the update waits for append
    /// admission, so a held local append guard excludes it. A recovery effect that revalidated its
    /// candidate's joined view under that guard therefore commits against that same roster.
    pub fn update_members_chirho(
        &self,
        new_members_chirho: Vec<(u64, NodeIdChirho)>,
    ) -> Result<()> {
        let mut seen_ids_chirho: BTreeSet<u64> = BTreeSet::new();
        let mut seen_nodes_chirho: BTreeSet<&NodeIdChirho> = BTreeSet::new();
        for (raft_id_chirho, node_chirho) in &new_members_chirho {
            if !seen_ids_chirho.insert(*raft_id_chirho) {
                bail!(
                    "update_members: raft id {raft_id_chirho} appears twice in the new authenticated set; refusing (an id must map to exactly one key)"
                );
            }
            if !seen_nodes_chirho.insert(node_chirho) {
                bail!(
                    "update_members: a node identity appears under two raft ids in the new authenticated set; refusing (one key must authenticate as exactly one member, else it could vote twice)"
                );
            }
        }
        match new_members_chirho
            .iter()
            .find(|(raft_id_chirho, _)| *raft_id_chirho == self.local_raft_id_chirho)
        {
            None => bail!(
                "update_members: the local node (raft id {}) is absent from the new authenticated set; refusing",
                self.local_raft_id_chirho
            ),
            Some((_, node_chirho)) if *node_chirho != self.node_id_chirho => bail!(
                "update_members: the local raft id {} is remapped to a different node identity; refusing",
                self.local_raft_id_chirho
            ),
            Some(_) => {}
        }
        self.with_roster_transition_chirho(|| {
            let mut guard_chirho = self
                .id_to_node_chirho
                .write()
                .unwrap_or_else(|poison_chirho| poison_chirho.into_inner());
            *guard_chirho = new_members_chirho;
            self.authenticated_roster_generation_chirho
                .fetch_update(Ordering::Release, Ordering::Relaxed, |generation_chirho| {
                    generation_chirho.checked_add(1)
                })
                .expect("authenticated roster generation exhausted");
        })
    }

    /// Run one roster swap while append admission is sealed, then republish the authority observation.
    ///
    /// Admission is taken first, holding nothing, so a held local append guard excludes the swap. The
    /// roster write lock is taken and released inside the swap, and only then does the republish read the
    /// node, so the roster and the RawNode are never held together: the same discipline the observation
    /// keeps. The republish records the update as a non-tick event, exactly as a Raft step does. It
    /// never moves the leadership start or the lease confirmation, so it cannot extend a lease past its
    /// original expiry. The warm-up flag is recomputed from those unchanged values, as any non-tick step
    /// recomputes it. So a leader whose warm-up time has passed while its confirmation is still live
    /// publishes as warm, and one whose confirmation has expired never does (gpt #29947). A panic in the
    /// swap leaves authority terminally poisoned, as for any transition, and a terminal observation is
    /// never republished.
    fn with_roster_transition_chirho(&self, swap_chirho: impl FnOnce()) -> Result<()> {
        catch_unwind(AssertUnwindSafe(|| {
            let authority_transition_chirho = self
                .local_append_authority_publisher_chirho
                .begin_transition_chirho();
            swap_chirho();
            let observation_chirho = {
                let node_chirho = self.lock_node_chirho();
                self.record_leader_tick_chirho(&node_chirho, false);
                self.local_append_authority_observation_chirho(&node_chirho)
            };
            authority_transition_chirho.publish_chirho(observation_chirho);
        }))
        .map_err(|_| {
            anyhow!("authenticated roster update panicked; local append authority is terminally poisoned")
        })
    }

    /// Exhaust the roster generation, so the next roster update panics after it has swapped the set.
    #[cfg(test)]
    pub(crate) fn exhaust_roster_generation_for_test_chirho(&self) {
        self.authenticated_roster_generation_chirho
            .store(u64::MAX, Ordering::Release);
    }
}
