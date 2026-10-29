// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A raft-rs-backed writer elector for ONE consistency group (D1 embedded Raft, shadow-first). It runs
//! the Raft consensus core for a cluster of voters and reads leadership. It is ELECTION-ONLY: it drives
//! consensus and reads the elected role, but applies no state machine and NEVER mints a fence.
//! `check_quorum` + `pre_vote` are on, so a leader that loses quorum steps down (the basis for
//! `lease_valid_chirho`) and a rejoining node cannot disrupt an election.
//!
//! Message passing (`tick_chirho`/`campaign_chirho`/`step_chirho` return the outbound Raft messages, and
//! `step_chirho` feeds an inbound one) is the impl-level seam a message TRANSPORT drives: an in-process
//! router proves multi-node election deterministically (slice 3a); an HTTP transport carries the same
//! messages between hosts (slice 3b). The `WriterElectorChirho` port itself stays leadership-only.

use crate::durable_store_chirho::DurableRaftStoreChirho;
use crate::elector_port_chirho::{
    LeadershipChirho, LeaseTierChirho, NodeIdChirho, WriterElectorChirho,
};
use crate::lease_composition_chirho::{
    election_timeout_monotonic_lease_chirho, MonotonicLeaseChirho, ELECTION_TICK_CHIRHO,
};
pub use crate::lease_composition_chirho::{
    election_timeout_upper_bound_chirho, validate_election_timeout_relay_margin_chirho,
};
use crate::local_append_authority_chirho::{
    local_append_authority_pair_chirho, local_append_authority_pair_with_monotonic_lease_chirho,
    LocalAppendAuthorityHandleChirho, LocalAppendAuthorityObservationChirho,
    LocalAppendAuthorityPublisherChirho,
};
use crate::monotonic_clock_chirho::MonotonicClockChirho;
use anyhow::{anyhow, bail, Result};
use std::sync::Arc;
// Re-exported: this type appears in the elector's public constructors, so consumers can name the
// authority-independent coordinate through the election-only crate.
pub use cairn_core_chirho::model_chirho::ConsistencyGroupIdChirho;
use prost::Message as ProstMessageChirho;
use raft::eraftpb::{
    ConfChangeSingle, ConfChangeType, ConfChangeV2, Entry, EntryType, Message, MessageType,
};
use raft::{Config, RawNode, StateRole, Storage};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, RwLock};
use std::time::Duration;

mod election_observation_chirho;
mod roster_update_chirho;
pub use election_observation_chirho::RaftElectionObservationChirho;

/// A leadership view that reports NO leader — the fail-safe returned when this elector governs a
/// different group, or when a read had to be contained after a crafted-message panic.
fn no_leadership_chirho() -> LeadershipChirho {
    LeadershipChirho {
        is_leader_chirho: false,
        leader_id_chirho: None,
        term_chirho: 0,
        lease_valid_chirho: false,
    }
}

/// The raft numeric id reserved for "no leader" (raft-rs uses 0).
const NO_LEADER_RAFT_ID_CHIRHO: u64 = 0;

/// A1.2 learner-then-promote: a learner may be promoted to a voter only once its replicated `matched`
/// index is within this many entries of the leader's last index — near enough that promoting it will
/// not stall the next commit waiting for it to catch up. A named, tested threshold (R5), not a bare
/// literal. The companion liveness window (how recently a peer must have answered to count as "live"
/// for the remove-quorum precheck) is the existing `ELECTION_TICK_CHIRHO`: raft's `check_quorum` resets
/// a peer's `recent_active` over that interval.
const CATCHUP_SLACK_CHIRHO: u64 = 8;

/// A single consistency group's Raft consensus node, wrapped as a `WriterElectorChirho`. Holds the
/// `RawNode` behind a `Mutex` so it can be driven from one task and read from others. The store is a
/// `DurableRaftStoreChirho`: an in-memory mirror for reads plus (when built durably) crash-safe on-disk
/// persistence of the term/vote, so a restart cannot double-vote. Ephemeral construction keeps the old
/// in-memory-only behavior for tests and non-recovering shadow runs.
pub struct RaftWriterElectorChirho {
    node_id_chirho: NodeIdChirho,
    group_chirho: ConsistencyGroupIdChirho,
    local_raft_id_chirho: u64,
    /// raft numeric id -> node identity (the ed25519 pubkey hex), to map the elected leader's id back to
    /// its pubkey AND to authenticate inbound messages against the sender's key. Behind an `RwLock` so the
    /// A1.3 convergence driver can update the authenticated peer set LIVE (add/remove a member on a
    /// running elector, no restart) via `update_members_chirho`; the auth/leadership reads take a cheap
    /// cloned snapshot so the lock is never held across the `raw_node_chirho` lock.
    id_to_node_chirho: RwLock<Vec<(u64, NodeIdChirho)>>,
    /// Advances after each complete authenticated-roster replacement. A production observation reads
    /// this generation before and after one raw-Raft snapshot; a mismatch refuses/retries instead of
    /// returning coordinates that straddled convergence. No path holds both locks together.
    authenticated_roster_generation_chirho: AtomicU64,
    /// When set, this node's signing root: outbound encoded messages are SIGNED with its key and inbound
    /// encoded messages are VERIFIED against the roster before `step`. When `None`, the encoded wire is
    /// bare (unauthenticated) — for the in-process tests and single-host shadow that need no transport
    /// authentication. The pubkey at this root must match this node's roster identity.
    sign_root_chirho: Option<PathBuf>,
    /// How many consecutive TICKS this node has been the leader (reset to 0 the moment it is not leader).
    /// The leadership-warm-up lease reads this. Written only under the `raw_node_chirho` lock (in
    /// tick/step/campaign) and read under it (in `leadership_chirho`), so it stays consistent with the
    /// node's role; `AtomicU64` avoids a second lock.
    leader_tick_count_chirho: AtomicU64,
    /// When true, `lease_valid_chirho` applies leadership warm-up instead of the raw `is_leader` bit.
    /// Shadow callers may opt into the legacy tick-counted form; deployable tier 1 sets this only while
    /// constructor-minting the monotonic lease and local-authority pair. The bit alone is never
    /// authority.
    lease_warmup_enabled_chirho: bool,
    /// The F1 lease: a monotonic clock plus the two durations that make the lease DECAY. Absent means
    /// the legacy tick-counted behaviour, which never expires and is why F1 exists.
    monotonic_lease_chirho: Option<MonotonicLeaseChirho>,
    /// Clock reading when this node most recently BECAME leader (0 = not leader). Warm-up is measured
    /// from here, so a flap cannot present as warmed.
    leadership_since_ms_chirho: AtomicU64,
    /// Clock reading when leadership was most recently CONFIRMED by a tick (0 = not leader). Expiry is
    /// measured from here, which is the whole point: if nobody ticks, nothing refreshes it and the
    /// lease decays on its own.
    leadership_confirmed_ms_chirho: AtomicU64,
    /// This elector's sealed publisher handles local `RawNode` transitions; the public handle only
    /// acquires fixed-field generation guards and cannot mint a fence or commit a journal.
    local_append_authority_publisher_chirho: LocalAppendAuthorityPublisherChirho,
    local_append_authority_handle_chirho: LocalAppendAuthorityHandleChirho,
    raw_node_chirho: Mutex<RawNode<DurableRaftStoreChirho>>,
}

impl RaftWriterElectorChirho {
    /// Build an EPHEMERAL single-node elector for `group_chirho`: the local node is the sole voter (raft
    /// id 1) and self-elects. In-memory only (no crash recovery) — for tests and non-recovering shadow.
    pub fn new_single_node_chirho(
        node_id_chirho: NodeIdChirho,
        group_chirho: ConsistencyGroupIdChirho,
    ) -> Result<Self> {
        Self::new_cluster_node_chirho(group_chirho, 1, vec![(1, node_id_chirho)])
    }

    /// Build an ephemeral node with its tier-1 lease and append-authority pair minted together.
    pub fn new_single_node_with_election_timeout_monotonic_leadership_lease_chirho(
        node_id_chirho: NodeIdChirho,
        group_chirho: ConsistencyGroupIdChirho,
        clock_chirho: Arc<dyn MonotonicClockChirho>,
        driver_tick_interval_chirho: Duration,
    ) -> Result<Self> {
        let monotonic_lease_chirho =
            election_timeout_monotonic_lease_chirho(clock_chirho, driver_tick_interval_chirho)?;
        Self::new_cluster_node_with_learners_and_monotonic_lease_chirho(
            group_chirho,
            1,
            vec![(1, node_id_chirho)],
            Vec::new(),
            Some(monotonic_lease_chirho),
        )
    }

    #[cfg(test)]
    pub(crate) fn new_single_node_with_monotonic_leadership_lease_chirho(
        node_id_chirho: NodeIdChirho,
        group_chirho: ConsistencyGroupIdChirho,
        clock_chirho: Arc<dyn MonotonicClockChirho>,
        warmup_millis_chirho: u64,
        expiry_millis_chirho: u64,
    ) -> Result<Self> {
        Self::new_cluster_node_with_learners_and_monotonic_lease_chirho(
            group_chirho,
            1,
            vec![(1, node_id_chirho)],
            Vec::new(),
            Some(MonotonicLeaseChirho {
                clock_chirho,
                warmup_millis_chirho,
                expiry_millis_chirho,
            }),
        )
    }

    /// Build an EPHEMERAL cluster-member elector: `local_raft_id_chirho` is this node's raft id, and
    /// `voters_chirho` is the full `(raft_id, node_id)` voter set (which must include this node). The node
    /// starts as a follower and participates in elections over the messages exchanged via
    /// `tick`/`campaign`/`step`. In-memory only — its term/vote do not survive a restart.
    pub fn new_cluster_node_chirho(
        group_chirho: ConsistencyGroupIdChirho,
        local_raft_id_chirho: u64,
        voters_chirho: Vec<(u64, NodeIdChirho)>,
    ) -> Result<Self> {
        Self::new_cluster_node_with_learners_chirho(
            group_chirho,
            local_raft_id_chirho,
            voters_chirho,
            Vec::new(),
        )
    }

    /// Build an EPHEMERAL cluster-member elector WITH non-voting learners — the async DR replicas of the
    /// geo model. `voters_chirho` are the voting quorum (commit waits on a majority of THESE, so a
    /// home-region quorum commits without a cross-geo hop); `learners_chirho` replicate the log but never
    /// count toward the quorum and can never be elected. `local_raft_id_chirho` may be a voter OR a
    /// learner (a learner node runs the same elector, in learner mode).
    pub fn new_cluster_node_with_learners_chirho(
        group_chirho: ConsistencyGroupIdChirho,
        local_raft_id_chirho: u64,
        voters_chirho: Vec<(u64, NodeIdChirho)>,
        learners_chirho: Vec<(u64, NodeIdChirho)>,
    ) -> Result<Self> {
        Self::new_cluster_node_with_learners_and_monotonic_lease_chirho(
            group_chirho,
            local_raft_id_chirho,
            voters_chirho,
            learners_chirho,
            None,
        )
    }

    fn new_cluster_node_with_learners_and_monotonic_lease_chirho(
        group_chirho: ConsistencyGroupIdChirho,
        local_raft_id_chirho: u64,
        voters_chirho: Vec<(u64, NodeIdChirho)>,
        learners_chirho: Vec<(u64, NodeIdChirho)>,
        monotonic_lease_chirho: Option<MonotonicLeaseChirho>,
    ) -> Result<Self> {
        let members_chirho =
            resolve_members_chirho(local_raft_id_chirho, voters_chirho, learners_chirho)?;
        let storage_chirho = DurableRaftStoreChirho::ephemeral_with_learners_chirho(
            members_chirho.voter_ids_chirho.clone(),
            members_chirho.learner_ids_chirho.clone(),
        );
        Self::assemble_chirho(
            group_chirho,
            local_raft_id_chirho,
            members_chirho.roster_chirho,
            members_chirho.node_id_chirho,
            storage_chirho,
            monotonic_lease_chirho,
        )
    }

    /// Build a DURABLE single-node elector rooted at `dir_chirho`: the same as `new_single_node_chirho`
    /// but its term/vote and log are persisted, so a crash + reopen on the same directory recovers them.
    pub fn new_durable_single_node_chirho(
        dir_chirho: PathBuf,
        node_id_chirho: NodeIdChirho,
        group_chirho: ConsistencyGroupIdChirho,
    ) -> Result<Self> {
        Self::new_durable_cluster_node_chirho(
            dir_chirho,
            group_chirho,
            1,
            vec![(1, node_id_chirho)],
        )
    }

    /// Reopen the durable single-node elector created by an earlier authority ceremony. Missing
    /// membership state is a refusal; this constructor never seeds a fresh election generation.
    pub fn open_existing_durable_single_node_chirho(
        dir_chirho: PathBuf,
        node_id_chirho: NodeIdChirho,
        group_chirho: ConsistencyGroupIdChirho,
    ) -> Result<Self> {
        Self::open_existing_durable_cluster_node_chirho(
            dir_chirho,
            group_chirho,
            1,
            vec![(1, node_id_chirho)],
        )
    }

    /// Reopen a previously initialized durable multi-node elector without creating a directory or
    /// seeding membership. The recovered voter set must exactly equal the expected signed roster;
    /// authority-bearing serving must never silently accept a different or half-applied quorum.
    pub fn open_existing_durable_cluster_node_chirho(
        dir_chirho: PathBuf,
        group_chirho: ConsistencyGroupIdChirho,
        local_raft_id_chirho: u64,
        voters_chirho: Vec<(u64, NodeIdChirho)>,
    ) -> Result<Self> {
        Self::open_existing_durable_cluster_node_with_learners_chirho(
            dir_chirho,
            group_chirho,
            local_raft_id_chirho,
            voters_chirho,
            Vec::new(),
        )
    }

    /// Existing-only durable cluster reopen with voters and non-voting learners.
    ///
    /// This refuses missing state, recovered membership drift, and an in-progress joint consensus
    /// transition. The caller must supply the exact currently signed roster rather than relying on a
    /// constructor argument to overwrite durable consensus state.
    pub fn open_existing_durable_cluster_node_with_learners_chirho(
        dir_chirho: PathBuf,
        group_chirho: ConsistencyGroupIdChirho,
        local_raft_id_chirho: u64,
        voters_chirho: Vec<(u64, NodeIdChirho)>,
        learners_chirho: Vec<(u64, NodeIdChirho)>,
    ) -> Result<Self> {
        Self::open_existing_durable_cluster_node_with_learners_and_monotonic_lease_chirho(
            dir_chirho,
            group_chirho,
            local_raft_id_chirho,
            voters_chirho,
            learners_chirho,
            None,
        )
    }

    /// Reopen a durable node with its tier-1 lease and append-authority pair minted together.
    pub fn open_existing_durable_cluster_node_with_learners_and_election_timeout_monotonic_lease_chirho(
        dir_chirho: PathBuf,
        group_chirho: ConsistencyGroupIdChirho,
        local_raft_id_chirho: u64,
        voters_chirho: Vec<(u64, NodeIdChirho)>,
        learners_chirho: Vec<(u64, NodeIdChirho)>,
        clock_chirho: Arc<dyn MonotonicClockChirho>,
        driver_tick_interval_chirho: Duration,
    ) -> Result<Self> {
        let monotonic_lease_chirho =
            election_timeout_monotonic_lease_chirho(clock_chirho, driver_tick_interval_chirho)?;
        Self::open_existing_durable_cluster_node_with_learners_and_monotonic_lease_chirho(
            dir_chirho,
            group_chirho,
            local_raft_id_chirho,
            voters_chirho,
            learners_chirho,
            Some(monotonic_lease_chirho),
        )
    }

    fn open_existing_durable_cluster_node_with_learners_and_monotonic_lease_chirho(
        dir_chirho: PathBuf,
        group_chirho: ConsistencyGroupIdChirho,
        local_raft_id_chirho: u64,
        voters_chirho: Vec<(u64, NodeIdChirho)>,
        learners_chirho: Vec<(u64, NodeIdChirho)>,
        monotonic_lease_chirho: Option<MonotonicLeaseChirho>,
    ) -> Result<Self> {
        let members_chirho =
            resolve_members_chirho(local_raft_id_chirho, voters_chirho, learners_chirho)?;
        let storage_chirho = DurableRaftStoreChirho::open_existing_with_learners_chirho(
            dir_chirho,
            members_chirho.voter_ids_chirho.clone(),
            members_chirho.learner_ids_chirho.clone(),
        )?;
        verify_recovered_membership_chirho(
            &storage_chirho,
            &members_chirho.voter_ids_chirho,
            &members_chirho.learner_ids_chirho,
        )?;
        Self::assemble_chirho(
            group_chirho,
            local_raft_id_chirho,
            members_chirho.roster_chirho,
            members_chirho.node_id_chirho,
            storage_chirho,
            monotonic_lease_chirho,
        )
    }

    /// Build a DURABLE cluster-member elector rooted at `dir_chirho`: the same as
    /// `new_cluster_node_chirho`, but the store persists the hard state (term/vote/commit), conf state,
    /// and log entries to `dir_chirho`, recovering them if the directory already holds a prior run's
    /// state. This is the crash-safe form a real host uses; the election stays non-authoritative
    /// (shadow) until the P5 cutover.
    pub fn new_durable_cluster_node_chirho(
        dir_chirho: PathBuf,
        group_chirho: ConsistencyGroupIdChirho,
        local_raft_id_chirho: u64,
        voters_chirho: Vec<(u64, NodeIdChirho)>,
    ) -> Result<Self> {
        Self::new_durable_cluster_node_with_learners_chirho(
            dir_chirho,
            group_chirho,
            local_raft_id_chirho,
            voters_chirho,
            Vec::new(),
        )
    }

    #[cfg(test)]
    pub(crate) fn new_durable_cluster_node_with_monotonic_leadership_lease_chirho(
        dir_chirho: PathBuf,
        group_chirho: ConsistencyGroupIdChirho,
        local_raft_id_chirho: u64,
        voters_chirho: Vec<(u64, NodeIdChirho)>,
        clock_chirho: Arc<dyn MonotonicClockChirho>,
        warmup_millis_chirho: u64,
        expiry_millis_chirho: u64,
    ) -> Result<Self> {
        Self::new_durable_cluster_node_with_learners_and_monotonic_lease_chirho(
            dir_chirho,
            group_chirho,
            local_raft_id_chirho,
            voters_chirho,
            Vec::new(),
            Some(MonotonicLeaseChirho {
                clock_chirho,
                warmup_millis_chirho,
                expiry_millis_chirho,
            }),
        )
    }

    /// The DURABLE, crash-safe form of `new_cluster_node_with_learners_chirho`: voters + non-voting
    /// learners persisted in `dir_chirho` (the conf state, term/vote, and log survive a restart).
    pub fn new_durable_cluster_node_with_learners_chirho(
        dir_chirho: PathBuf,
        group_chirho: ConsistencyGroupIdChirho,
        local_raft_id_chirho: u64,
        voters_chirho: Vec<(u64, NodeIdChirho)>,
        learners_chirho: Vec<(u64, NodeIdChirho)>,
    ) -> Result<Self> {
        Self::new_durable_cluster_node_with_learners_and_monotonic_lease_chirho(
            dir_chirho,
            group_chirho,
            local_raft_id_chirho,
            voters_chirho,
            learners_chirho,
            None,
        )
    }

    /// Build a durable node with its tier-1 lease and append-authority pair minted together.
    pub fn new_durable_cluster_node_with_learners_and_election_timeout_monotonic_lease_chirho(
        dir_chirho: PathBuf,
        group_chirho: ConsistencyGroupIdChirho,
        local_raft_id_chirho: u64,
        voters_chirho: Vec<(u64, NodeIdChirho)>,
        learners_chirho: Vec<(u64, NodeIdChirho)>,
        clock_chirho: Arc<dyn MonotonicClockChirho>,
        driver_tick_interval_chirho: Duration,
    ) -> Result<Self> {
        let monotonic_lease_chirho =
            election_timeout_monotonic_lease_chirho(clock_chirho, driver_tick_interval_chirho)?;
        Self::new_durable_cluster_node_with_learners_and_monotonic_lease_chirho(
            dir_chirho,
            group_chirho,
            local_raft_id_chirho,
            voters_chirho,
            learners_chirho,
            Some(monotonic_lease_chirho),
        )
    }

    fn new_durable_cluster_node_with_learners_and_monotonic_lease_chirho(
        dir_chirho: PathBuf,
        group_chirho: ConsistencyGroupIdChirho,
        local_raft_id_chirho: u64,
        voters_chirho: Vec<(u64, NodeIdChirho)>,
        learners_chirho: Vec<(u64, NodeIdChirho)>,
        monotonic_lease_chirho: Option<MonotonicLeaseChirho>,
    ) -> Result<Self> {
        let members_chirho =
            resolve_members_chirho(local_raft_id_chirho, voters_chirho, learners_chirho)?;
        let storage_chirho = DurableRaftStoreChirho::open_with_learners_chirho(
            dir_chirho,
            members_chirho.voter_ids_chirho.clone(),
            members_chirho.learner_ids_chirho.clone(),
        )?;
        Self::assemble_chirho(
            group_chirho,
            local_raft_id_chirho,
            members_chirho.roster_chirho,
            members_chirho.node_id_chirho,
            storage_chirho,
            monotonic_lease_chirho,
        )
    }

    /// Validate the Raft config and assemble an elector around a prepared store.
    fn assemble_chirho(
        group_chirho: ConsistencyGroupIdChirho,
        local_raft_id_chirho: u64,
        voters_chirho: Vec<(u64, NodeIdChirho)>,
        node_id_chirho: NodeIdChirho,
        storage_chirho: DurableRaftStoreChirho,
        monotonic_lease_chirho: Option<MonotonicLeaseChirho>,
    ) -> Result<Self> {
        // Feed the applied index recovered from the durable membership file (0 if fresh/ephemeral) so a
        // committed-but-unpersisted conf change re-surfaces exactly once on restart, and an
        // already-persisted one does not (R1/R2).
        let applied_index_chirho = storage_chirho.recovered_applied_index_chirho();
        let config_chirho = Config {
            id: local_raft_id_chirho,
            election_tick: ELECTION_TICK_CHIRHO,
            heartbeat_tick: 3,
            check_quorum: true,
            pre_vote: true,
            applied: applied_index_chirho,
            ..Default::default()
        };
        config_chirho
            .validate()
            .map_err(|e_chirho| anyhow!("raft config invalid: {e_chirho}"))?;
        let logger_chirho = slog::Logger::root(slog::Discard, slog::o!());
        let raw_node_chirho = RawNode::new(&config_chirho, storage_chirho, &logger_chirho)
            .map_err(|e_chirho| anyhow!("raft raw node: {e_chirho}"))?;
        let (local_append_authority_publisher_chirho, local_append_authority_handle_chirho) =
            match monotonic_lease_chirho.as_ref() {
                Some(lease_chirho) => local_append_authority_pair_with_monotonic_lease_chirho(
                    group_chirho.clone(),
                    node_id_chirho.clone(),
                    Arc::clone(&lease_chirho.clock_chirho),
                    lease_chirho.expiry_millis_chirho,
                ),
                None => {
                    local_append_authority_pair_chirho(group_chirho.clone(), node_id_chirho.clone())
                }
            };
        let lease_warmup_enabled_chirho = monotonic_lease_chirho.is_some();
        Ok(Self {
            node_id_chirho,
            group_chirho,
            local_raft_id_chirho,
            id_to_node_chirho: RwLock::new(voters_chirho),
            authenticated_roster_generation_chirho: AtomicU64::new(0),
            sign_root_chirho: None,
            leader_tick_count_chirho: AtomicU64::new(0),
            lease_warmup_enabled_chirho,
            monotonic_lease_chirho,
            leadership_since_ms_chirho: AtomicU64::new(0),
            leadership_confirmed_ms_chirho: AtomicU64::new(0),
            local_append_authority_publisher_chirho,
            local_append_authority_handle_chirho,
            raw_node_chirho: Mutex::new(raw_node_chirho),
        })
    }

    /// Enable transport authentication: sign outbound encoded messages with the node key at
    /// `sign_root_chirho`, and verify inbound encoded messages against the roster before `step`. The
    /// pubkey provisioned at that root MUST equal this node's roster identity, or peers will reject this
    /// node's messages (the signature would verify against a different key). A builder method so the
    /// authenticated form is opt-in on top of any elector construction.
    pub fn with_message_authentication_chirho(mut self, sign_root_chirho: PathBuf) -> Self {
        self.sign_root_chirho = Some(sign_root_chirho);
        self
    }

    /// How much of this node's lease REMAINS, in milliseconds, or `None` if it holds none.
    ///
    /// A duration rather than a deadline or a boolean, because this is what crosses a process
    /// boundary. A boolean loses the clock — true when it left, with no way for a receiver to price
    /// the delay. A monotonic instant loses the DOMAIN — monotonic clocks have arbitrary per-process
    /// origins, so a sender's instant compared against a receiver's clock type-checks and yields
    /// plausible garbage. A remaining duration survives both, and the receiver converts it against
    /// its own clock on arrival.
    pub fn lease_remaining_millis_chirho(
        &self,
        group_chirho: &ConsistencyGroupIdChirho,
    ) -> Option<u64> {
        let lease_chirho = self.monotonic_lease_chirho.as_ref()?;
        // THIS GATE CARRIES THE WARM-UP PREDICATE, AND IT IS THE ONLY THING THAT DOES. The elapsed
        // arithmetic below is monotone in ONE axis — how much of `expiry` is left — and warm-up is not
        // on that axis at all, so removing this check does not weaken a bound, it deletes a dimension.
        // An unwarmed leader was just confirmed by the tick that warmed nothing, so `elapsed` is ~0 and
        // the arithmetic alone would return the FULL expiry: maximal advertised validity at the moment
        // the node is least entitled to any. The receiver cannot catch that — every protection there
        // resolves toward LESS time and none shrinks a large well-formed value.
        if !self.leadership_chirho(group_chirho).lease_valid_chirho {
            return None;
        }
        let now_chirho = lease_chirho.clock_chirho.now_millis_chirho();
        let confirmed_chirho = self.leadership_confirmed_ms_chirho.load(Ordering::Relaxed);
        let elapsed_chirho = now_chirho.checked_sub(confirmed_chirho)?;
        lease_chirho
            .expiry_millis_chirho
            .checked_sub(elapsed_chirho)
            .filter(|remaining_chirho| *remaining_chirho > 0)
    }

    /// Enable the legacy tick-counted leadership warm-up: `lease_valid_chirho` becomes true only after
    /// this node has been leader for a full `ELECTION_TICK_CHIRHO`. It has no elapsed-time expiry and no
    /// quorum-recency meaning. Opt-in and non-authoritative for bounded shadow/test callers only.
    pub fn with_leadership_warmup_lease_chirho(mut self) -> Self {
        self.lease_warmup_enabled_chirho = true;
        self
    }

    /// This node's raft numeric id.
    pub fn local_raft_id_chirho(&self) -> u64 {
        self.local_raft_id_chirho
    }

    /// Return the append-authority handle paired with this exact elector instance. The caller supplies
    /// no group and cannot construct or rebind a handle independently.
    pub fn local_append_authority_handle_chirho(&self) -> LocalAppendAuthorityHandleChirho {
        self.local_append_authority_handle_chirho.clone()
    }

    /// WHICH of the three predicates in `leadership_chirho` produces this node's `lease_valid_chirho`.
    ///
    /// Safe to serialise, unlike the boolean it describes: the tier is a property of how this node is
    /// CONFIGURED, fixed for the elector's lifetime, so it cannot go stale in transit.
    ///
    /// **DIAGNOSIS ONLY — it does not carry validity, and must never be read as if it did.**
    /// `lease_remaining_millis_chirho` returns `None` for BOTH "tier 1, lease expired" and "tiers 2/3,
    /// this node has no monotonic lease at all" — the early `?` on `monotonic_lease_chirho`. The tier
    /// says WHICH of those two a `None` means. That is its whole job.
    ///
    /// **It cannot say whether the predicate PASSED.** This value is derived purely from configuration,
    /// so a just-elected UNWARMED tier-2 leader and a fully warmed one produce identical
    /// `TickWarmupChirho` + `remaining = None`. A receiver that treated that pair as valid would
    /// authorize an unwarmed leader.
    ///
    /// Two arms pin this, and they cover different things: `the_two_lease_accessors_carry_no_warm_
    /// state_chirho` (this crate) witnesses the ACCESSORS, while
    /// `unwarmed_and_warmed_tier_two_leaders_send_byte_identical_responses_chirho` in
    /// `cairn-writer-elector-http-chirho` drives the production handler and is the only one that
    /// witnesses the WIRE.
    ///
    /// **Non-monotonic tiers stay non-authoritative on the wire.** The only authority-relevant lease
    /// path is the DURATION, re-anchored by `lease_deadline_from_remaining_chirho`, which takes no tier
    /// and cannot be influenced by one.
    ///
    /// **This mirrors the branch in `leadership_chirho` and must keep mirroring it** — same conditions,
    /// same order. The correspondence is pinned by
    /// `the_advertised_tier_matches_the_branch_that_computed_validity_chirho`; if you move one branch,
    /// that test tells you which one you missed.
    pub fn lease_tier_chirho(&self) -> LeaseTierChirho {
        if self.monotonic_lease_chirho.is_some() {
            LeaseTierChirho::MonotonicDecayChirho
        } else if self.lease_warmup_enabled_chirho {
            LeaseTierChirho::TickWarmupChirho
        } else {
            LeaseTierChirho::RawRoleChirho
        }
    }

    /// Update the consecutive-leader tick count after a node operation, holding the node lock (so the
    /// count stays consistent with the role). A non-leader resets it to 0; a clock TICK while leader
    /// increments it; a non-tick event (step/campaign) leaves it (no logical time passed) — and because a
    /// node that just became leader was reset to 0 while it was a follower, its warm-up starts from 0.
    fn record_leader_tick_chirho(
        &self,
        node_chirho: &RawNode<DurableRaftStoreChirho>,
        is_clock_tick_chirho: bool,
    ) {
        if node_chirho.raft.state != StateRole::Leader {
            self.leader_tick_count_chirho.store(0, Ordering::Relaxed);
            self.leadership_since_ms_chirho.store(0, Ordering::Relaxed);
            self.leadership_confirmed_ms_chirho
                .store(0, Ordering::Relaxed);
        } else if is_clock_tick_chirho {
            let previous_chirho = self.leader_tick_count_chirho.load(Ordering::Relaxed);
            self.leader_tick_count_chirho
                .store(previous_chirho.saturating_add(1), Ordering::Relaxed);
            if let Some(lease_chirho) = &self.monotonic_lease_chirho {
                // `max(1)` keeps 0 meaning "not leader" even at clock origin.
                let now_chirho = lease_chirho.clock_chirho.now_millis_chirho().max(1);
                let _ = self.leadership_since_ms_chirho.compare_exchange(
                    0,
                    now_chirho,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
                self.leadership_confirmed_ms_chirho
                    .store(now_chirho, Ordering::Relaxed);
            }
        }
    }

    /// Lock the `RawNode`, recovering the inner value if a prior panic poisoned the mutex — so a single
    /// crafted-message panic can NEVER permanently brick this node's elector. (raft-rs 0.7 panics on
    /// some crafted messages, e.g. an out-of-range `MsgAppend` with `prevLogTerm=0`; we contain that
    /// panic below and must not let the poisoned mutex turn one bad request into a permanent DoS.)
    fn lock_node_chirho(&self) -> MutexGuard<'_, RawNode<DurableRaftStoreChirho>> {
        self.raw_node_chirho
            .lock()
            .unwrap_or_else(|poisoned_chirho| poisoned_chirho.into_inner())
    }

    /// Run one complete local `RawNode` transition while append admission is sealed.
    ///
    /// The publisher marks the transition pending before waiting for an in-flight append guard, then
    /// invalidates authority before this function locks or mutates the node. A normal error leaves
    /// authority terminally poisoned, as does a panic. Only reconstructing the elector from durable
    /// state may create a new authority pair after either failure. Outbound encoding/signing/network work
    /// remains outside this helper and therefore outside the generation gate.
    fn with_raw_node_transition_chirho<TChirho>(
        &self,
        is_clock_tick_chirho: bool,
        panic_message_chirho: &'static str,
        transition_chirho: impl FnOnce(&mut RawNode<DurableRaftStoreChirho>) -> Result<TChirho>,
    ) -> Result<TChirho> {
        catch_unwind(AssertUnwindSafe(|| {
            let authority_transition_chirho = self
                .local_append_authority_publisher_chirho
                .begin_transition_chirho();
            let transition_result_chirho = {
                let mut node_chirho = self.lock_node_chirho();
                transition_chirho(&mut node_chirho).map(|result_chirho| {
                    self.record_leader_tick_chirho(&node_chirho, is_clock_tick_chirho);
                    let observation_chirho =
                        self.local_append_authority_observation_chirho(&node_chirho);
                    (result_chirho, observation_chirho)
                })
            };
            let (result_chirho, observation_chirho) = match transition_result_chirho {
                Ok(success_chirho) => success_chirho,
                Err(error_chirho) => {
                    authority_transition_chirho.fail_terminal_chirho();
                    return Err(error_chirho);
                }
            };
            authority_transition_chirho.publish_chirho(observation_chirho);
            Ok(result_chirho)
        }))
        .unwrap_or_else(|_| Err(anyhow!(panic_message_chirho)))
    }

    /// Snapshot only the fixed fields append admission needs. This runs after a local transition while
    /// the `RawNode` lock is already held; the hot `try_acquire_chirho` path never reaches the node.
    fn local_append_authority_observation_chirho(
        &self,
        node_chirho: &RawNode<DurableRaftStoreChirho>,
    ) -> LocalAppendAuthorityObservationChirho {
        let local_is_leader_chirho = node_chirho.raft.state == StateRole::Leader
            && node_chirho.raft.leader_id == self.local_raft_id_chirho;
        let leader_tick_count_chirho = self.leader_tick_count_chirho.load(Ordering::Relaxed);
        LocalAppendAuthorityObservationChirho {
            local_is_leader_chirho,
            warmup_lease_valid_chirho: if self.monotonic_lease_chirho.is_some() {
                self.monotonic_lease_valid_for_role_chirho(local_is_leader_chirho)
            } else {
                self.lease_warmup_enabled_chirho
                    && local_is_leader_chirho
                    && leader_tick_count_chirho >= ELECTION_TICK_CHIRHO as u64
            },
            lease_confirmed_millis_chirho: self
                .leadership_confirmed_ms_chirho
                .load(Ordering::Relaxed),
            local_is_promotable_voter_chirho: node_chirho.raft.promotable(),
            transfer_in_progress_chirho: node_chirho.raft.lead_transferee.is_some(),
            published_raft_term_chirho: node_chirho.raft.term,
        }
    }

    /// Advance the Raft logical clock once and process any resulting `Ready`, returning the outbound
    /// messages to deliver to peers. Call on a timer to drive elections and heartbeats.
    pub fn tick_chirho(&self) -> Vec<Message> {
        self.with_raw_node_transition_chirho(true, "raft tick transition panicked", |node_chirho| {
            node_chirho.tick();
            Ok(drain_ready_chirho(node_chirho))
        })
        .unwrap_or_default()
    }

    /// Feed an inbound Raft message from a peer, process the resulting `Ready`, and return this node's
    /// outbound messages to deliver next — the transport's inbound entrypoint. An election-only node
    /// never needs a snapshot (it never compacts), and a crafted inbound `MsgSnapshot` desyncs raft from
    /// the store, so it is dropped at the boundary. Any panic raft-rs raises on another crafted message
    /// is CONTAINED here as an error — never a poisoned mutex or a permanently bricked node (shadow is
    /// non-authoritative; a wedged node is surfaced by the canary, not a crash).
    pub fn step_chirho(&self, message_chirho: Message) -> Result<Vec<Message>> {
        if message_chirho.msg_type() == MessageType::MsgSnapshot {
            return Ok(Vec::new());
        }
        self.with_raw_node_transition_chirho(
            false,
            "raft step panicked on a rejected/crafted message",
            move |node_chirho| {
                node_chirho
                    .step(message_chirho)
                    .map_err(|e_chirho| anyhow!("raft step: {e_chirho}"))?;
                Ok(drain_ready_chirho(node_chirho))
            },
        )
    }

    /// Force an election now (pre-vote → vote) and return the outbound messages that carry it. A
    /// deterministic way to start an election without waiting for the election timeout.
    pub fn campaign_chirho(&self) -> Result<Vec<Message>> {
        self.with_raw_node_transition_chirho(false, "raft campaign panicked", |node_chirho| {
            node_chirho
                .campaign()
                .map_err(|e_chirho| anyhow!("raft campaign: {e_chirho}"))?;
            Ok(drain_ready_chirho(node_chirho))
        })
    }

    /// The transport-facing form of `step_chirho`: feed one inbound message as wire BYTES, and get back
    /// `(target_raft_id, wire_bytes)` for each outbound message. A transport routes by the id and moves
    /// the bytes, never touching a raft type. When authentication is enabled the inbound bytes are a
    /// SIGNED envelope, verified against the roster (the message's `from` must be a rostered peer whose
    /// key signed it) BEFORE `step` — so a forged/tampered message is rejected here, never stepped.
    pub fn step_encoded_chirho(&self, message_bytes_chirho: &[u8]) -> Result<Vec<(u64, Vec<u8>)>> {
        let message_chirho = match &self.sign_root_chirho {
            Some(_) => {
                // Snapshot the authenticated set and release the lock BEFORE `step` locks
                // `raw_node_chirho` (no lock-order inversion); the clone is negligible next to the verify.
                let roster_chirho = self.authenticated_roster_snapshot_chirho();
                crate::raft_wire_chirho::decode_and_verify_message_chirho(
                    message_bytes_chirho,
                    &self.group_chirho,
                    self.local_raft_id_chirho,
                    &roster_chirho,
                )?
            }
            None => crate::raft_wire_chirho::decode_message_chirho(message_bytes_chirho)?,
        };
        self.encode_outbound_chirho(self.step_chirho(message_chirho)?)
    }

    /// The transport-facing form of `campaign_chirho`: campaign and get `(target_raft_id, wire_bytes)`
    /// for each outbound message (signed when authentication is enabled).
    pub fn campaign_encoded_chirho(&self) -> Result<Vec<(u64, Vec<u8>)>> {
        self.encode_outbound_chirho(self.campaign_chirho()?)
    }

    /// The transport-facing form of `tick_chirho`: advance the logical clock once and get
    /// `(target_raft_id, wire_bytes)` for each outbound message (signed when authentication is enabled).
    /// This is the PRODUCTION election trigger — a background driver calls it on a timer, and a node whose
    /// election timeout elapses starts an election with no explicit `campaign`.
    pub fn tick_encoded_chirho(&self) -> Result<Vec<(u64, Vec<u8>)>> {
        self.encode_outbound_chirho(self.tick_chirho())
    }

    /// Ask Raft to transfer leadership to `target_raft_id_chirho`, returning the messages that hand it
    /// over (a transport delivers them; the target then campaigns and takes over). This is the primitive
    /// behind "pin the master back to its home region once it heals" — call it on the current leader
    /// (raft forwards or drops it otherwise). A crafted-message panic is contained like the other node
    /// ops. Election mechanics only: it mints nothing.
    pub fn transfer_leadership_to_chirho(
        &self,
        target_raft_id_chirho: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>> {
        let outbound_chirho = self
            .with_raw_node_transition_chirho(
                false,
                "raft leadership transfer panicked",
                |node_chirho| {
                    node_chirho.transfer_leader(target_raft_id_chirho);
                    Ok(drain_ready_chirho(node_chirho))
                },
            )
            .unwrap_or_default();
        self.encode_outbound_chirho(outbound_chirho)
    }

    /// Propose ONE membership change on this (leader) node — the A1.1 apply-side entrypoint. Enforces the
    /// single-server-change rule (R3a): a proposal must carry EXACTLY one change, so no proposal can
    /// create a transition with two disjoint majorities. raft-rs enforces the second barrier itself — it
    /// rejects a proposal while a prior conf change is still pending (`pending_conf_index`) and a
    /// non-leader cannot propose — and those surface here as an `Err`, never a silent no-op. The
    /// convergence driver (A1.2/A1.3) adds the new-leader term-commit barrier on top. Returns the
    /// outbound messages that carry the proposal to followers.
    pub fn propose_conf_change_chirho(
        &self,
        context_chirho: Vec<u8>,
        conf_change_chirho: ConfChangeV2,
    ) -> Result<Vec<(u64, Vec<u8>)>> {
        if conf_change_chirho.changes.len() != 1 {
            bail!(
                "A1 single-server-change rule: a proposal must carry exactly one change, got {}",
                conf_change_chirho.changes.len()
            );
        }
        let outbound_chirho = self.with_raw_node_transition_chirho(
            false,
            "raft propose conf change panicked",
            |node_chirho| {
                node_chirho
                    .propose_conf_change(context_chirho, conf_change_chirho)
                    .map_err(|e_chirho| anyhow!("raft propose conf change: {e_chirho}"))?;
                Ok(drain_ready_chirho(node_chirho))
            },
        )?;
        self.encode_outbound_chirho(outbound_chirho)
    }

    #[cfg(test)]
    pub(crate) fn inject_local_append_authority_error_chirho(&self) -> Result<()> {
        self.with_raw_node_transition_chirho(
            false,
            "injected local append-authority error panicked",
            |_node_chirho| Err(anyhow!("injected local append-authority transition error")),
        )
    }

    #[cfg(test)]
    pub(crate) fn inject_local_append_authority_panic_chirho(&self) -> Result<()> {
        self.with_raw_node_transition_chirho(
            false,
            "injected local append-authority transition panic",
            |node_chirho| {
                node_chirho.tick();
                if node_chirho.has_ready() {
                    let _ready_chirho = node_chirho.ready();
                }
                panic!("injected local append-authority transition panic after RawNode mutation")
            },
        )
    }

    /// The current applied membership as sorted `(voter_ids, learner_ids)` — read from the store's conf
    /// state, which `apply_conf_change` updates. For assertions and the convergence driver's diff.
    pub fn membership_snapshot_chirho(&self) -> Result<(Vec<u64>, Vec<u64>)> {
        let node_chirho = self.lock_node_chirho();
        let state_chirho = node_chirho
            .raft
            .raft_log
            .store
            .initial_state()
            .map_err(|e_chirho| anyhow!("read raft conf state: {e_chirho}"))?;
        let mut voters_chirho = state_chirho.conf_state.voters.clone();
        let mut learners_chirho = state_chirho.conf_state.learners.clone();
        voters_chirho.sort_unstable();
        learners_chirho.sort_unstable();
        Ok((voters_chirho, learners_chirho))
    }

    /// The durable last-applied conf-change index (A1.5 observability, R6): the on-disk highwater the
    /// membership file carries, so a drill can assert over HTTP that a committed membership change actually
    /// applied + persisted. Clones the cheap store handle and releases the node lock BEFORE the tiny file
    /// read, so observability never blocks a tick across I/O. Never used for a correctness decision.
    pub fn applied_conf_index_chirho(&self) -> Result<u64> {
        let store_chirho = {
            let node_chirho = self.lock_node_chirho();
            node_chirho.raft.raft_log.store.clone()
        };
        store_chirho.durable_applied_conf_index_chirho()
    }

    /// A snapshot of the authenticated peer set (raft id -> node identity). Cloned so the `RwLock` is
    /// released immediately — the auth path must NOT hold it across the `raw_node_chirho` lock (that would
    /// invert the lock order), and the clone (a handful of `(u64, hex)` pairs) is negligible next to the
    /// ed25519 verify it feeds. Recovers a poisoned lock: the only writer (`update_members_chirho`) swaps
    /// the whole set in one assignment, so the data is always a whole set. A panic after that assignment
    /// happens inside the admission seal, so it also leaves local append authority terminally poisoned.
    fn authenticated_roster_snapshot_chirho(&self) -> Vec<(u64, NodeIdChirho)> {
        self.id_to_node_chirho
            .read()
            .unwrap_or_else(|poison_chirho| poison_chirho.into_inner())
            .clone()
    }

    /// The raft ids currently in the authenticated peer set, sorted ascending — for the convergence driver
    /// to assert the set tracks membership, and for tests. Ids only (non-secret); the pubkeys stay internal.
    pub fn authenticated_member_ids_chirho(&self) -> Vec<u64> {
        let mut ids_chirho: Vec<u64> = self
            .authenticated_roster_snapshot_chirho()
            .into_iter()
            .map(|(raft_id_chirho, _)| raft_id_chirho)
            .collect();
        ids_chirho.sort_unstable();
        ids_chirho
    }

    /// The current authenticated peer set as `(raft_id, node_identity)` pairs — the read the convergence
    /// driver needs to compute the next auth set incrementally (add the joining peer, drop the leaving
    /// one) and hand it back to `update_members_chirho`. Node identities are ed25519 PUBLIC keys, so this
    /// is non-secret. (The convergence driver is the sole auth-set mutator on a node, so its
    /// read-then-`update_members` sequence has no competing writer.)
    pub fn authenticated_members_chirho(&self) -> Vec<(u64, NodeIdChirho)> {
        self.authenticated_roster_snapshot_chirho()
    }

    /// Turn a batch of outbound raft messages into `(target_raft_id, wire_bytes)` pairs for a transport.
    /// When authentication is enabled each message is encoded as a SIGNED envelope with this node's key;
    /// otherwise it is the bare prost bytes. Signing can fail (missing/bad key), which surfaces as an
    /// error rather than an unsigned message slipping onto the wire.
    fn encode_outbound_chirho(&self, messages_chirho: Vec<Message>) -> Result<Vec<(u64, Vec<u8>)>> {
        messages_chirho
            .iter()
            .map(|message_chirho| {
                let bytes_chirho = match &self.sign_root_chirho {
                    Some(sign_root_chirho) => {
                        crate::raft_wire_chirho::encode_signed_message_chirho(
                            message_chirho,
                            &self.group_chirho,
                            sign_root_chirho,
                        )?
                    }
                    None => crate::raft_wire_chirho::encode_message_chirho(message_chirho),
                };
                Ok((message_chirho.to, bytes_chirho))
            })
            .collect()
    }

    /// Propose adding a node as a non-voting LEARNER — the first half of the safe add protocol
    /// (learner-then-promote). A learner replicates the log but never counts toward the commit quorum and
    /// can never be elected, so admitting a cold node cannot stall commits or split the vote.
    ///
    /// REFUSES to add an id that is ALREADY A VOTER: in raft-rs an `AddLearnerNode` on a current voter is
    /// not an add but a DEMOTION (voter → learner), which silently shrinks the voting quorum — the exact
    /// hazard `remove_node_chirho` guards. So a mistranslated roster row (a re-listed voter id) can never
    /// become a quorum shrink. An id that is already a learner is an idempotent no-op. Leader-only for the
    /// proposal (a follower's or pending-conf proposal surfaces as an `Err`).
    pub fn add_learner_chirho(&self, raft_id_chirho: u64) -> Result<AddLearnerOutcomeChirho> {
        let (voter_ids_chirho, learner_ids_chirho) = self.membership_snapshot_chirho()?;
        if voter_ids_chirho.contains(&raft_id_chirho) {
            return Ok(AddLearnerOutcomeChirho::AlreadyVoterChirho { raft_id_chirho });
        }
        if learner_ids_chirho.contains(&raft_id_chirho) {
            return Ok(AddLearnerOutcomeChirho::AlreadyLearnerChirho { raft_id_chirho });
        }
        let outbound_chirho = self.propose_conf_change_chirho(
            Vec::new(),
            single_conf_change_chirho(ConfChangeType::AddLearnerNode, raft_id_chirho),
        )?;
        Ok(AddLearnerOutcomeChirho::ProposedChirho(outbound_chirho))
    }

    /// Read whether `raft_id_chirho` is caught up enough to promote to a voter: its replicated `matched`
    /// index is within `CATCHUP_SLACK_CHIRHO` of the leader's last log index AND the leader still marks it
    /// recent-active (it answered within the last `ELECTION_TICK_CHIRHO` window). Read under the node
    /// lock, panic-contained (a node corrupted by a prior crafted message reads as not-caught-up); `false`
    /// for an id with no tracked progress.
    pub fn learner_caught_up_chirho(&self, raft_id_chirho: u64) -> bool {
        catch_unwind(AssertUnwindSafe(|| {
            let node_chirho = self.lock_node_chirho();
            let last_index_chirho = node_chirho.raft.raft_log.last_index();
            match node_chirho.raft.prs().get(raft_id_chirho) {
                Some(progress_chirho) => {
                    progress_chirho.recent_active
                        && progress_chirho.matched
                            >= last_index_chirho.saturating_sub(CATCHUP_SLACK_CHIRHO)
                }
                None => false,
            }
        }))
        .unwrap_or(false)
    }

    /// The second half of the safe add protocol: promote a caught-up learner to a full voter. If it is
    /// NOT yet caught up, DEFER (`NotCaughtUpChirho`) — the caller retries later and a lagging learner
    /// never wedges the group (it stays a harmless non-voting learner until it catches up or is removed).
    /// Leader-only.
    pub fn promote_learner_if_caught_up_chirho(
        &self,
        raft_id_chirho: u64,
    ) -> Result<PromoteOutcomeChirho> {
        let progress_chirho = catch_unwind(AssertUnwindSafe(|| {
            let node_chirho = self.lock_node_chirho();
            let last_index_chirho = node_chirho.raft.raft_log.last_index();
            node_chirho
                .raft
                .prs()
                .get(raft_id_chirho)
                .map(|p_chirho| (p_chirho.matched, p_chirho.recent_active, last_index_chirho))
        }))
        .unwrap_or(None);
        match progress_chirho {
            None => Ok(PromoteOutcomeChirho::UnknownMemberChirho),
            Some((matched_chirho, recent_active_chirho, last_index_chirho)) => {
                if recent_active_chirho
                    && matched_chirho >= last_index_chirho.saturating_sub(CATCHUP_SLACK_CHIRHO)
                {
                    let outbound_chirho = self.propose_conf_change_chirho(
                        Vec::new(),
                        single_conf_change_chirho(ConfChangeType::AddNode, raft_id_chirho),
                    )?;
                    Ok(PromoteOutcomeChirho::ProposedChirho(outbound_chirho))
                } else {
                    Ok(PromoteOutcomeChirho::NotCaughtUpChirho {
                        matched_chirho,
                        last_index_chirho,
                    })
                }
            }
        }
    }

    /// Remove a node, quorum-safe. Refuses two unsafe cases and proposes only when it is safe:
    /// - if `raft_id_chirho` is the CURRENT leader, returns `MustTransferLeadershipFirstChirho` (R4) — the
    ///   caller transfers leadership away (P4 mechanics) and retries, so the group is never left with its
    ///   leader outside its own config;
    /// - if removing it would drop the group below a live majority, returns `WouldBreakQuorumChirho` — the
    ///   removal could not even commit, so refusing keeps the group from wedging.
    ///
    /// "Live" is the leader's `recent_active` view of each remaining voter (the local leader counts
    /// itself). This is an OPERATIONAL guard: liveness can change between this check and the commit —
    /// raft's overlapping-majority property, not this check, is the safety proof. Leader-only.
    pub fn remove_node_chirho(&self, raft_id_chirho: u64) -> Result<RemoveOutcomeChirho> {
        let decision_chirho = catch_unwind(AssertUnwindSafe(|| {
            let node_chirho = self.lock_node_chirho();
            let is_current_leader_target_chirho = node_chirho.raft.leader_id == raft_id_chirho
                && raft_id_chirho != NO_LEADER_RAFT_ID_CHIRHO;
            let voter_ids_chirho = node_chirho
                .raft
                .raft_log
                .store
                .initial_state()
                .map(|state_chirho| state_chirho.conf_state.voters)
                .unwrap_or_default();
            let voters_after_chirho: Vec<u64> = voter_ids_chirho
                .into_iter()
                .filter(|voter_chirho| *voter_chirho != raft_id_chirho)
                .collect();
            let live_after_chirho = voters_after_chirho
                .iter()
                .filter(|voter_chirho| {
                    **voter_chirho == self.local_raft_id_chirho
                        || node_chirho
                            .raft
                            .prs()
                            .get(**voter_chirho)
                            .is_some_and(|progress_chirho| progress_chirho.recent_active)
                })
                .count();
            (
                is_current_leader_target_chirho,
                voters_after_chirho.len(),
                live_after_chirho,
            )
        }));
        let (is_leader_target_chirho, voters_after_chirho, live_after_chirho) =
            decision_chirho.map_err(|_| anyhow!("read for remove precheck panicked"))?;
        if is_leader_target_chirho {
            return Ok(RemoveOutcomeChirho::MustTransferLeadershipFirstChirho {
                leader_raft_id_chirho: raft_id_chirho,
            });
        }
        let needed_chirho = voters_after_chirho / 2 + 1;
        if live_after_chirho < needed_chirho {
            return Ok(RemoveOutcomeChirho::WouldBreakQuorumChirho {
                live_voters_after_chirho: live_after_chirho,
                needed_chirho,
            });
        }
        let outbound_chirho = self.propose_conf_change_chirho(
            Vec::new(),
            single_conf_change_chirho(ConfChangeType::RemoveNode, raft_id_chirho),
        )?;
        Ok(RemoveOutcomeChirho::ProposedChirho(outbound_chirho))
    }
}

/// The outcome of a guarded learner add (`add_learner_chirho`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddLearnerOutcomeChirho {
    /// The id was not a member; adding it as a non-voting learner was proposed — deliver these messages.
    ProposedChirho(Vec<(u64, Vec<u8>)>),
    /// The id is ALREADY A VOTER; refused, because `AddLearnerNode` on a voter DEMOTES it and shrinks the
    /// voting quorum. Keep it a voter, or `remove_node_chirho` then re-add if a demotion is truly intended.
    AlreadyVoterChirho { raft_id_chirho: u64 },
    /// The id is already a learner; nothing to do (idempotent no-op) — no proposal was made.
    AlreadyLearnerChirho { raft_id_chirho: u64 },
}

/// The outcome of a guarded learner promotion (`promote_learner_if_caught_up_chirho`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromoteOutcomeChirho {
    /// The learner was caught up; the promotion (add-voter) was proposed — deliver these messages.
    ProposedChirho(Vec<(u64, Vec<u8>)>),
    /// The learner is not yet caught up; promotion is DEFERRED (surfaced, never wedged) — retry later.
    NotCaughtUpChirho {
        matched_chirho: u64,
        last_index_chirho: u64,
    },
    /// No progress is tracked for that id on this leader (not a current member).
    UnknownMemberChirho,
}

/// The outcome of a guarded node removal (`remove_node_chirho`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoveOutcomeChirho {
    /// The remove was quorum-safe and was proposed — deliver these messages.
    ProposedChirho(Vec<(u64, Vec<u8>)>),
    /// The target is the CURRENT leader; transfer leadership away first (R4), then retry the remove.
    MustTransferLeadershipFirstChirho { leader_raft_id_chirho: u64 },
    /// Removing the target would drop the group below a live majority; refused (never wedged).
    WouldBreakQuorumChirho {
        live_voters_after_chirho: usize,
        needed_chirho: usize,
    },
}

/// Process one `Ready` for an ELECTION-ONLY node and return the outbound messages to deliver. There is
/// no state machine to apply, so we durably persist the log entries + hard state (in that order, so an
/// entry is on disk before it is acknowledged), advance, and durably record the commit index, collecting
/// every outbound message (pre-persist, persisted, and post-advance) in raft-rs's required order.
/// (Snapshots do not arise without log compaction, which this never does.) A durable-write failure
/// panics here and is CONTAINED by the `catch_unwind` in the tick/step/campaign callers — a wedged
/// shadow node is surfaced by the canary, never a poisoned mutex or a crash.
fn drain_ready_chirho(node_chirho: &mut RawNode<DurableRaftStoreChirho>) -> Vec<Message> {
    let mut outbound_chirho = Vec::new();
    if !node_chirho.has_ready() {
        return outbound_chirho;
    }
    let store_chirho = node_chirho.raft.raft_log.store.clone();
    let mut ready_chirho = node_chirho.ready();
    // Messages that may be sent before the entries/hard-state are persisted.
    outbound_chirho.append(&mut ready_chirho.take_messages());
    // Take the committed entries now (owned), but APPLY them only after the entries + hard state are
    // durable below. Applying a membership change persists {conf', applied=i}; if that landed BEFORE
    // this ready's hard state (commit=i), a crash between the two writes would leave applied=i on disk
    // while durable commit=i-1, and raft-rs panics at construction on reopen (applied ahead of commit).
    // Persist-then-apply (the canonical raft loop, matching the light phase below) closes that window.
    let committed_chirho = ready_chirho.take_committed_entries();
    if !ready_chirho.entries().is_empty() {
        store_chirho
            .append_durable_chirho(ready_chirho.entries())
            .expect("durably append raft entries");
    }
    if let Some(hard_state_chirho) = ready_chirho.hs() {
        store_chirho
            .set_hardstate_durable_chirho(hard_state_chirho.clone())
            .expect("durably persist raft hard state");
    }
    // Entries + hard state are now durable, so a committed membership change persists its applied index
    // only after the commit index that authorizes it — no applied-ahead-of-commit window.
    apply_committed_entries_chirho(node_chirho, &store_chirho, committed_chirho);
    // Messages that must only be sent AFTER the above persist.
    outbound_chirho.append(&mut ready_chirho.take_persisted_messages());
    let mut light_ready_chirho = node_chirho.advance(ready_chirho);
    if let Some(commit_chirho) = light_ready_chirho.commit_index() {
        store_chirho
            .set_commit_durable_chirho(commit_chirho)
            .expect("durably persist raft commit index");
    }
    outbound_chirho.append(&mut light_ready_chirho.take_messages());
    // Membership changes committed during `advance` are applied here, same as the ready phase.
    let light_committed_chirho = light_ready_chirho.take_committed_entries();
    apply_committed_entries_chirho(node_chirho, &store_chirho, light_committed_chirho);
    node_chirho.advance_apply();
    outbound_chirho
}

/// Build a single-change `ConfChangeV2` (the only shape `propose_conf_change_chirho` accepts): add a
/// voter, add a non-voting learner, or remove a node, by raft id. The convergence driver and the tests
/// build proposals through this so the one-change invariant is expressed at the construction site too.
// eraftpb structs carry hidden fields, so `default()` + field assignment is the idiomatic build.
#[allow(clippy::field_reassign_with_default)]
pub fn single_conf_change_chirho(
    change_type_chirho: ConfChangeType,
    raft_id_chirho: u64,
) -> ConfChangeV2 {
    let mut single_chirho = ConfChangeSingle::default();
    single_chirho.set_change_type(change_type_chirho);
    single_chirho.node_id = raft_id_chirho;
    let mut conf_change_chirho = ConfChangeV2::default();
    conf_change_chirho.changes = vec![single_chirho];
    conf_change_chirho
}

/// Apply the committed entries of an election-only node. The only entries with a side effect are
/// membership changes (`ConfChangeV2`): each is applied to the raft node via `apply_conf_change` and the
/// resulting `ConfState` persisted together with the entry's index as the applied highwater mark (R1),
/// so a restart recovers the exact membership and never re-applies a persisted change. A committed
/// normal entry (a leader's no-op) has no state machine to touch. A decode or apply failure panics and
/// is CONTAINED by the caller's `catch_unwind` (a wedged shadow node is surfaced by the canary, never a
/// crash) — a committed entry is raft-authored, so a failure here is a bug, not attacker input.
fn apply_committed_entries_chirho(
    node_chirho: &mut RawNode<DurableRaftStoreChirho>,
    store_chirho: &DurableRaftStoreChirho,
    entries_chirho: Vec<Entry>,
) {
    for entry_chirho in entries_chirho {
        // An empty entry (a leader's term no-op) carries no change; only conf-change entries have data
        // this node acts on.
        if entry_chirho.entry_type() != EntryType::EntryConfChangeV2 || entry_chirho.data.is_empty()
        {
            continue;
        }
        let conf_change_chirho = ConfChangeV2::decode(&entry_chirho.data[..])
            .expect("decode committed ConfChangeV2 entry");
        let new_conf_state_chirho = node_chirho
            .apply_conf_change(&conf_change_chirho)
            .expect("apply committed membership change");
        store_chirho
            .set_conf_state_durable_chirho(new_conf_state_chirho, entry_chirho.index)
            .expect("durably persist applied membership change");
    }
}

fn verify_recovered_membership_chirho(
    storage_chirho: &DurableRaftStoreChirho,
    expected_voters_chirho: &[u64],
    expected_learners_chirho: &[u64],
) -> Result<()> {
    let state_chirho = storage_chirho
        .initial_state()
        .map_err(|error_chirho| anyhow!("read recovered raft membership: {error_chirho}"))?;
    let conf_chirho = state_chirho.conf_state;
    if !conf_chirho.voters_outgoing.is_empty()
        || !conf_chirho.learners_next.is_empty()
        || conf_chirho.auto_leave
    {
        bail!("recovered raft membership is inside a joint consensus transition");
    }
    let mut actual_voters_chirho = conf_chirho.voters;
    let mut actual_learners_chirho = conf_chirho.learners;
    let mut expected_voters_chirho = expected_voters_chirho.to_vec();
    let mut expected_learners_chirho = expected_learners_chirho.to_vec();
    actual_voters_chirho.sort_unstable();
    actual_learners_chirho.sort_unstable();
    expected_voters_chirho.sort_unstable();
    expected_learners_chirho.sort_unstable();
    if actual_voters_chirho != expected_voters_chirho
        || actual_learners_chirho != expected_learners_chirho
    {
        bail!("recovered raft membership differs from the expected signed roster");
    }
    Ok(())
}

/// The resolved membership for an elector: this node's identity, the voter and learner raft ids (for the
/// conf state) and the combined `(raft_id, node_id)` roster (voters + learners) used to map a leader id
/// back to its pubkey and to authenticate inbound messages.
struct ResolvedMembersChirho {
    node_id_chirho: NodeIdChirho,
    voter_ids_chirho: Vec<u64>,
    learner_ids_chirho: Vec<u64>,
    roster_chirho: Vec<(u64, NodeIdChirho)>,
}

/// Resolve `local_raft_id_chirho`'s identity from the voter + learner sets, collecting the raft ids and
/// the combined roster. Errors if the local id is in neither set.
fn resolve_members_chirho(
    local_raft_id_chirho: u64,
    voters_chirho: Vec<(u64, NodeIdChirho)>,
    learners_chirho: Vec<(u64, NodeIdChirho)>,
) -> Result<ResolvedMembersChirho> {
    let voter_ids_chirho: Vec<u64> = voters_chirho
        .iter()
        .map(|(raft_id_chirho, _)| *raft_id_chirho)
        .collect();
    let learner_ids_chirho: Vec<u64> = learners_chirho
        .iter()
        .map(|(raft_id_chirho, _)| *raft_id_chirho)
        .collect();
    // A raft id may be a voter OR a learner, never both — raft-rs PANICS on an overlapping conf state
    // (it refuses to silently demote a voter), so reject it here as a clean error rather than crashing
    // the caller thread at construction.
    if let Some(overlap_chirho) = learner_ids_chirho
        .iter()
        .find(|learner_id_chirho| voter_ids_chirho.contains(learner_id_chirho))
    {
        return Err(anyhow!(
            "raft id {overlap_chirho} is listed as both a voter and a learner"
        ));
    }
    let mut roster_chirho = voters_chirho;
    roster_chirho.extend(learners_chirho);
    let node_id_chirho = roster_chirho
        .iter()
        .find(|(raft_id_chirho, _)| *raft_id_chirho == local_raft_id_chirho)
        .map(|(_, node_chirho)| node_chirho.clone())
        .ok_or_else(|| {
            anyhow!("local raft id {local_raft_id_chirho} is not in the voter or learner set")
        })?;
    Ok(ResolvedMembersChirho {
        node_id_chirho,
        voter_ids_chirho,
        learner_ids_chirho,
        roster_chirho,
    })
}

impl WriterElectorChirho for RaftWriterElectorChirho {
    fn leadership_chirho(&self, group_chirho: &ConsistencyGroupIdChirho) -> LeadershipChirho {
        // This elector governs exactly one group; a query for a different group is not-leader here.
        if group_chirho != &self.group_chirho {
            return no_leadership_chirho();
        }
        // Read leadership under panic containment: a node corrupted by a prior crafted message must not
        // crash the canary's read path — it reads as no-leader (fail-safe, and surfaced by the canary).
        let read_chirho = catch_unwind(AssertUnwindSafe(|| {
            let node_chirho = self.lock_node_chirho();
            let status_chirho = node_chirho.status();
            // Read the leader-tick count under the SAME lock as the role, so the warm-up lease is
            // computed from a consistent (role, count) pair.
            let leader_tick_count_chirho = self.leader_tick_count_chirho.load(Ordering::Relaxed);
            (
                status_chirho.ss.raft_state == StateRole::Leader,
                status_chirho.ss.leader_id,
                status_chirho.hs.term,
                leader_tick_count_chirho,
            )
        }));
        let (is_leader_chirho, leader_raft_id_chirho, term_chirho, leader_tick_count_chirho) =
            match read_chirho {
                Ok(quad_chirho) => quad_chirho,
                Err(_) => return no_leadership_chirho(),
            };
        let leader_id_chirho = if leader_raft_id_chirho == NO_LEADER_RAFT_ID_CHIRHO {
            None
        } else {
            self.authenticated_roster_snapshot_chirho()
                .iter()
                .find(|(raft_id_chirho, _)| *raft_id_chirho == leader_raft_id_chirho)
                .map(|(_, node_chirho)| node_chirho.clone())
        };
        // `lease_valid_chirho` is a local liveness predicate. The monotonic form warms for one election
        // interval and expires when this process's ticker stops; it is not proof of recent quorum contact
        // and cannot own cross-host write safety. Exact composite fencing plus GD7 own that boundary.
        // Without the opt-in it is the raw `is_leader` role bit (single-host shadow only).
        let lease_valid_chirho = if self.monotonic_lease_chirho.is_some() {
            // A tick is LOCAL progress, not quorum contact. Under ordinary cadence, raft's
            // `check_quorum` steps down a disconnected leader after its logical election window. A
            // sufficiently slow-scheduled old leader can still refresh this local duration while a
            // healthy majority elects elsewhere, so this predicate MUST NOT be cited as a quorum lease
            // or cross-host write-safety proof. Exact composite fencing plus GD7 own that boundary.
            //
            // The distinct local failure this lease closes is a stopped ticker: `check_quorum` cannot
            // advance, the stale role bit can remain Leader, but elapsed monotonic time still expires.
            //
            // THE F1 LEASE. Two clauses, and the second is the one that was missing: leadership must
            // have been held long enough (so a flap is not warmed) AND confirmed recently enough (so
            // it DECAYS when nobody is ticking). A leader whose tick driver died refreshes nothing,
            // so its lease goes invalid without anyone calling anything.
            // EVERY CLAUSE OF THIS PREDICATE HAS A NAMED DISPOSITION. If you change one, find its row.
            //   expiry clause                 PINNED — the decay arm (mutation M1)
            //   warm-up clause                PINNED — the decay arm (mutation M3)
            //   what may REFRESH `confirmed`  PINNED — only_a_clock_tick_may_refresh_the_lease_… (M2)
            //   how this crosses a BOUNDARY   PINNED — an_unwarmed_leader_advertises_no_lease_… (M4)
            //   what may CLEAR `is_leader`    PINNED — a_partitioned_leader_loses_its_lease_through_
            //                                 step_down_not_expiry_chirho, which excludes the other two
            //                                 clauses BY CONSTRUCTION (expiry 1_000_000ms vs a clock
            //                                 advancing at most 4_000ms; warm-up satisfied before the
            //                                 partition; the leader keeps ticking) so only the role
            //                                 remains
            //   `since` set-once semantics    SAFE-DIRECTION, deliberately unpinned: a plain store keeps
            //                                 (now − since) near zero, so the warm-up never elapses and
            //                                 the lease never validates — availability, not safety
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

    fn node_id_chirho(&self) -> &NodeIdChirho {
        &self.node_id_chirho
    }
}
