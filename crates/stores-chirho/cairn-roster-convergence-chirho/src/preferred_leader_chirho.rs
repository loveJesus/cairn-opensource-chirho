// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A1.4 slice 2b: the election-only transfer-BACK driver. The derivation (slice 2a,
//! `derive_preferred_leader_chirho`) gives the POLICY — the operator-signed preferred write leader for a
//! group; this applies the SAFETY — it hands leadership to that node when it is a caught-up healthy
//! voter, and otherwise leaves the current leader where it is. This is L.J.'s "the write primary moves,
//! and moves BACK to the primary audience's home on heal": while the preferred node is down the transfer
//! times out and the current leader stays (no availability loss), and it re-homes automatically once the
//! preferred heals and catches up. Election-only — it mints nothing and moves no head.

use anyhow::Result;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;

/// Encoded `(target_raft_id, wire_bytes)` outbound messages a transport must deliver — the same shape the
/// elector's encoded methods return.
type OutboundMessagesChirho = Vec<(u64, Vec<u8>)>;

/// What one re-home step did — or why it left leadership where it is (always surfaced).
/// `Serialize`/`Deserialize` so the A1.5 `/re-home-chirho` control endpoint can return the executed step
/// as its JSON evidence body.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ReHomeStepChirho {
    /// No signed preference for this group — leadership is left wherever it currently is.
    NoPreferenceChirho,
    /// This node is not the leader, so it cannot hand off leadership — nothing done.
    NotLeaderChirho,
    /// This node IS the preferred leader and already leads — the primary is home; nothing to do.
    AlreadyPreferredChirho,
    /// The preferred node is not currently a voter (a learner or absent), so it cannot become leader —
    /// leadership left put; it becomes eligible once it is promoted to a voter.
    PreferredNotVoterChirho { raft_id_chirho: u64 },
    /// A leadership transfer to the preferred voter was initiated (raft completes it once the target is
    /// caught up; if the target is down the transfer times out and this node stays leader).
    TransferringChirho { to_raft_id_chirho: u64 },
}

/// Move write leadership one safe step toward the operator's preferred leader for a group, returning the
/// step outcome AND any outbound `(target_raft_id, wire_bytes)` the caller's transport must deliver.
///
/// `preferred_raft_id_chirho` is the derived policy (from `derive_preferred_leader_chirho`): `None` when
/// the operator signed no preference. Priority: no preference → leave put; this node not the leader →
/// leave put (only the leader transfers); this node already the preferred → nothing; the preferred not a
/// voter → leave put; else initiate `transfer_leadership_to` the preferred voter. The transfer emits a
/// one-shot `MsgTimeoutNow` (a control message, not a replicated log entry, so `tick` will NOT re-send
/// it) — hence it is returned here for the caller to deliver, exactly like the elector's other encoded
/// methods. `transfer_leadership_to` is raft-safe: it catches the target up first, and a transfer to a
/// DOWN node times out with this node staying leader — so quorum/availability never dips and the group
/// re-homes on heal. Mints nothing, moves no head.
pub fn re_home_step_chirho(
    elector_chirho: &RaftWriterElectorChirho,
    preferred_raft_id_chirho: Option<u64>,
) -> Result<(ReHomeStepChirho, OutboundMessagesChirho)> {
    let Some(preferred_chirho) = preferred_raft_id_chirho else {
        return Ok((ReHomeStepChirho::NoPreferenceChirho, Vec::new()));
    };
    // Only the current leader can hand off leadership.
    if !elector_chirho.current_leadership_chirho().is_leader_chirho {
        return Ok((ReHomeStepChirho::NotLeaderChirho, Vec::new()));
    }
    // This node is the preferred and already leads — the primary is home.
    if elector_chirho.local_raft_id_chirho() == preferred_chirho {
        return Ok((ReHomeStepChirho::AlreadyPreferredChirho, Vec::new()));
    }
    // The preferred must be a VOTER to become leader; a learner/absent node cannot lead.
    let (voters_chirho, _learners_chirho) = elector_chirho.membership_snapshot_chirho()?;
    if !voters_chirho.contains(&preferred_chirho) {
        return Ok((
            ReHomeStepChirho::PreferredNotVoterChirho {
                raft_id_chirho: preferred_chirho,
            },
            Vec::new(),
        ));
    }
    // Initiate the raft-safe transfer back to the preferred voter; return its wire messages to deliver.
    // A1.4 audit LOW (deferred, now folded): a TransferringChirho carrying an EMPTY message batch is benign
    // — transfer_leadership_to's contained-panic/degraded fallback can return no messages, so the caller
    // pumps nothing, the transfer simply does not fire this round, leadership stays put, and the next
    // re-home call retries (identical to the down-target-timeout path). It is never a silent success that
    // moved the head.
    let messages_chirho = elector_chirho.transfer_leadership_to_chirho(preferred_chirho)?;
    Ok((
        ReHomeStepChirho::TransferringChirho {
            to_raft_id_chirho: preferred_chirho,
        },
        messages_chirho,
    ))
}
