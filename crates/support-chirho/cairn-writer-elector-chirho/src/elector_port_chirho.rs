// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The writer-election port + its n=1 baseline. The port is read-only leadership; the term is the Raft
//! term that BECOMES the monotonic fence epoch at the P5 cutover, and `lease_valid` is the additional
//! P5 gate before an elected leader may mint. In shadow mode these are observed, never enforced.

use cairn_core_chirho::model_chirho::ConsistencyGroupIdChirho;

/// A node's identity in the writer-election cluster = its ed25519 public key (hex). This is the SAME
/// identity used as the P3 replication-source id, the D3 roster node id, and each root's head-signing
/// key — one identity across replication, membership, and head signing.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct NodeIdChirho(pub String);

/// The current leadership view for one consistency group.
///
/// - `term_chirho` is the Raft term. It is monotonic per group and, at the P5 cutover, becomes the
///   fence epoch a leader mints — so a stale-term (fenced-out) writer is rejected by the EXISTING
///   monotonic-epoch sinks with no change to them.
/// - `lease_valid_chirho` records the configured local liveness predicate. The deployable tier detects
///   a stopped local tick driver; it does not prove recent quorum contact. A write gate combines it
///   with `is_leader_chirho`, raft-rs `check_quorum` step-down, and the exact persisted fence. No one
///   component is sufficient by itself.
///
/// In SHADOW mode this is only observed and compared against the process that actually holds the fence;
/// it does not gate any write.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LeadershipChirho {
    pub is_leader_chirho: bool,
    pub leader_id_chirho: Option<NodeIdChirho>,
    pub term_chirho: u64,
    /// A LIVENESS signal, and deliberately NOT an authority signal. **It is never sufficient on its
    /// own to gate a money write.**
    ///
    /// Its expiry clause detects exactly one failure: that this node's tick driver stopped. It cannot
    /// see quorum loss at all — a tick fires whether or not any peer is reachable. Loss of authority
    /// is caught by raft's `check_quorum` step-down, which drops `is_leader_chirho`, and the two
    /// together are what make this field mean anything. That sufficiency is pinned by
    /// `a_partitioned_leader_loses_its_lease_through_step_down_not_expiry_chirho`; disabling
    /// `check_quorum` reddens it.
    ///
    /// Anchoring expiry on last successful QUORUM CONTACT would be strictly stronger and is the right
    /// eventual answer. It is deferred explicitly, not silently, because that evidence is not
    /// available at this layer.
    pub lease_valid_chirho: bool,
}

/// WHICH predicate produced a `lease_valid_chirho`, because a bare `true` means three different things
/// and only one of them decays.
///
/// A receiver that is told only "valid" cannot tell a monotonic lease that will expire in 40ms from a
/// raw role bit that is unsound cross-host. The tier is what makes the boolean readable, and it is
/// SAFE to serialise for the same reason the boolean is not: the tier is a property of how the
/// answering node is CONFIGURED, so it does not change in transit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LeaseTierChirho {
    /// The answering node predates this field — an older peer's response simply has no tier in it.
    ///
    /// It told us nothing, so a receiver must treat it as NOT lease-valid. This is the `serde` default
    /// deliberately: guessing a tier for a silent node would be a fabrication, and every other value
    /// here licenses MORE trust than "unknown" does.
    #[default]
    UnknownChirho,
    /// Tier 1 — warm-up AND expiry decay against a monotonic clock.
    ///
    /// The only tier whose validity is time-dependent, and therefore the only one that must NOT cross a
    /// wire as a boolean: it would be stale on arrival. It crosses as `lease_remaining_millis_chirho`
    /// and the receiver re-anchors that in its own clock domain.
    MonotonicDecayChirho,
    /// Tier 2 — leadership held for a full `ELECTION_TICK_CHIRHO`, counted in TICKS rather than
    /// milliseconds. It does not decay with wall-clock time, so it is stable in transit.
    TickWarmupChirho,
    /// Tier 3 — the raw role bit: no warm-up, no decay.
    ///
    /// Sound for a single-host shadow and UNSOUND cross-host, because two nodes either side of a
    /// partition can both hold the bit. A receiver seeing this tier knows the signal is weak.
    RawRoleChirho,
}

/// The read-only writer-election port (D4: swappable, so the raft-rs impl can be improved/replaced
/// without touching callers). It reports WHO the elected writer is for a consistency group. It NEVER
/// mints a fence or commits a head — the local fence lock still mints in shadow mode, and the elected
/// leader only gains mint authority at the separate, hard-gated P5 cutover.
pub trait WriterElectorChirho {
    /// The current (non-blocking) leadership view for a consistency group.
    fn leadership_chirho(&self, group_chirho: &ConsistencyGroupIdChirho) -> LeadershipChirho;
    /// This node's identity.
    fn node_id_chirho(&self) -> &NodeIdChirho;
}

/// The n=1 baseline: a single-node cluster's sole member is trivially and permanently the leader — this
/// is correct Raft semantics for a one-voter group, not a placeholder. It establishes the port and lets
/// the shadow canary be wired before the multi-node raft-rs elector arrives. It holds no fence and mints
/// nothing.
pub struct SingleNodeWriterElectorChirho {
    node_id_chirho: NodeIdChirho,
}

impl SingleNodeWriterElectorChirho {
    pub fn new_chirho(node_id_chirho: NodeIdChirho) -> Self {
        Self { node_id_chirho }
    }
}

impl WriterElectorChirho for SingleNodeWriterElectorChirho {
    fn leadership_chirho(&self, _group_chirho: &ConsistencyGroupIdChirho) -> LeadershipChirho {
        // A one-voter group elects itself at term 1 and holds a (trivially valid) lease.
        LeadershipChirho {
            is_leader_chirho: true,
            leader_id_chirho: Some(self.node_id_chirho.clone()),
            term_chirho: 1,
            lease_valid_chirho: true,
        }
    }

    fn node_id_chirho(&self) -> &NodeIdChirho {
        &self.node_id_chirho
    }
}
