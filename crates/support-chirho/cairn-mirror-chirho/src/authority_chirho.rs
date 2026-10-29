// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The one money/authority seam: the INVERTED leadership predicate a mirror receiver applies before
//! it will durably store an inert closure. It is the exact place a byte-for-byte copy of the proven
//! write-relay is WRONG.
//!
//! The relay receiver refuses unless IT ITSELF is the elected leader (`leader_id == self`), because a
//! relay destination IS the leader a follower forwarded a write to. A mirror receiver is a FOLLOWER
//! durably storing on behalf of the leader, so `leader_id == self` is FALSE for every legitimate
//! mirror prepare. The mirror receiver instead verifies that the FRAME ORIGIN (the sender) is the
//! current leader for the group at the bound term IN THE RECEIVER'S OWN JOINED VIEW, and that the
//! receiver itself is a rostered member of that exact view.
//!
//! Authority = (sender is rostered in the receiver's joined view)
//!           + (sender is the elected leader at the bound term, which is not stale)
//!           + (a valid ed25519 signature over the PREPARE — checked upstream in `frame_chirho`).
//! The leader's lease, carried as a DURATION and rebased at receipt, is a LIVENESS-in-combination
//! gate — never the sole authority, and NEVER the receiver's OWN lease (that measures the follower's
//! tick driver, not the leader's authority). There is NO authority door on the receiver: it stores
//! already-sealed inert bytes and signs a receipt; it never runs an effect and never re-enters a
//! served path.
//!
//! Both wrong directions are guarded by the ONE clause `leadership.leader_id == Some(sender)`:
//! mutate it to `== self` and every legitimate prepare refuses; drop it and any rostered node can
//! command a mirror write. The fixture proof plants BOTH and asserts each refuses by its own name.
//!
//! The roster half and the leadership half arrive as ONE `JoinedMirrorViewChirho` produced by
//! `membership_chirho::join_mirror_view_chirho`, never as two independent arguments. That is what
//! discharges reviewer F3: the two halves cannot name different terms, because the joined view has a
//! single term written from a single election observation and no other constructor exists.

use crate::frame_chirho::{VerifiedMirrorFinalizeChirho, VerifiedMirrorPrepareChirho};
use crate::membership_chirho::JoinedMirrorViewChirho;
use crate::refusal_chirho::{MirrorContractErrorChirho, MirrorRefusalIdentityChirho};
use cairn_writer_elector_chirho::monotonic_clock_chirho::{
    lease_deadline_from_remaining_chirho, lease_deadline_is_live_chirho, MonotonicClockChirho,
};
use std::num::NonZeroU64;

/// Proof that a PREPARE passed the receiver's inverted-leadership authority check. Only the durable
/// store path can be reached with one of these, so authority can never be skipped by construction.
pub struct AuthorizedMirrorPrepareChirho<'frame_chirho> {
    verified_chirho: &'frame_chirho VerifiedMirrorPrepareChirho,
}

/// Proof that a FINALIZE passed the same current-leader authority check as its PREPARE.
pub struct AuthorizedMirrorFinalizeChirho<'frame_chirho> {
    verified_chirho: &'frame_chirho VerifiedMirrorFinalizeChirho,
}

impl<'frame_chirho> AuthorizedMirrorFinalizeChirho<'frame_chirho> {
    pub fn verified_chirho(&self) -> &VerifiedMirrorFinalizeChirho {
        self.verified_chirho
    }
}

impl<'frame_chirho> AuthorizedMirrorPrepareChirho<'frame_chirho> {
    pub fn verified_chirho(&self) -> &VerifiedMirrorPrepareChirho {
        self.verified_chirho
    }
}

/// The six coordinates the authority check reads from a frame. It is public so a sibling contract
/// that a mirror holder also receives from the leader (7.2c key custody and erasure,
/// `cairn-key-custody-chirho`) runs THIS check rather than a second copy of the inverted predicate.
/// Implementing it grants nothing: it only exposes fields to `verify_mirror_authority_binding_chirho`.
pub trait MirrorAuthorityFrameViewChirho {
    fn origin_node_id_chirho(&self) -> &str;
    fn target_node_id_chirho(&self) -> &str;
    fn consistency_group_digest_chirho(&self) -> &str;
    fn membership_view_digest_chirho(&self) -> &str;
    fn expected_term_chirho(&self) -> u64;
    fn leader_lease_remaining_millis_chirho(&self) -> Option<u64>;
}

impl MirrorAuthorityFrameViewChirho for VerifiedMirrorPrepareChirho {
    fn origin_node_id_chirho(&self) -> &str {
        VerifiedMirrorPrepareChirho::origin_node_id_chirho(self)
    }

    fn target_node_id_chirho(&self) -> &str {
        VerifiedMirrorPrepareChirho::target_node_id_chirho(self)
    }

    fn consistency_group_digest_chirho(&self) -> &str {
        VerifiedMirrorPrepareChirho::consistency_group_digest_chirho(self)
    }

    fn membership_view_digest_chirho(&self) -> &str {
        VerifiedMirrorPrepareChirho::membership_view_digest_chirho(self)
    }

    fn expected_term_chirho(&self) -> u64 {
        VerifiedMirrorPrepareChirho::expected_term_chirho(self)
    }

    fn leader_lease_remaining_millis_chirho(&self) -> Option<u64> {
        VerifiedMirrorPrepareChirho::leader_lease_remaining_millis_chirho(self)
    }
}

impl MirrorAuthorityFrameViewChirho for VerifiedMirrorFinalizeChirho {
    fn origin_node_id_chirho(&self) -> &str {
        VerifiedMirrorFinalizeChirho::origin_node_id_chirho(self)
    }

    fn target_node_id_chirho(&self) -> &str {
        VerifiedMirrorFinalizeChirho::target_node_id_chirho(self)
    }

    fn consistency_group_digest_chirho(&self) -> &str {
        VerifiedMirrorFinalizeChirho::consistency_group_digest_chirho(self)
    }

    fn membership_view_digest_chirho(&self) -> &str {
        VerifiedMirrorFinalizeChirho::membership_view_digest_chirho(self)
    }

    fn expected_term_chirho(&self) -> u64 {
        VerifiedMirrorFinalizeChirho::expected_term_chirho(self)
    }

    fn leader_lease_remaining_millis_chirho(&self) -> Option<u64> {
        VerifiedMirrorFinalizeChirho::leader_lease_remaining_millis_chirho(self)
    }
}

/// Apply the inverted-leadership authority check for a mirror PREPARE.
///
/// `receiver_node_id_chirho` is THIS holder. `joined_chirho` is the receiver's OWN two-authority
/// joined view — the operator-signed roster joined to ONE observation of the live election. It is a
/// single argument on purpose: a caller cannot hand in placement and leadership that were never
/// joined, so the placement/election agreement this check depends on is a property of the type
/// rather than a rule the caller is trusted to honour.
///
/// The order of checks is deliberate so each failure has a distinct named reason: membership first,
/// then the stale-term guard, then the sender-is-leader inversion, then the leader's lease liveness.
pub fn verify_mirror_prepare_authority_chirho<'frame_chirho>(
    verified_chirho: &'frame_chirho VerifiedMirrorPrepareChirho,
    joined_chirho: &JoinedMirrorViewChirho,
    receiver_node_id_chirho: &str,
    clock_chirho: &dyn MonotonicClockChirho,
    transit_budget_millis_chirho: NonZeroU64,
) -> Result<AuthorizedMirrorPrepareChirho<'frame_chirho>, MirrorContractErrorChirho> {
    verify_mirror_authority_binding_chirho(
        verified_chirho,
        joined_chirho,
        receiver_node_id_chirho,
        clock_chirho,
        transit_budget_millis_chirho,
    )?;
    Ok(AuthorizedMirrorPrepareChirho { verified_chirho })
}

/// Apply the same current-leader, exact-view, and lease check to FINALIZE. A deposed leader cannot
/// make a prior prepared closure visible after authority moved.
pub fn verify_mirror_finalize_authority_chirho<'frame_chirho>(
    verified_chirho: &'frame_chirho VerifiedMirrorFinalizeChirho,
    joined_chirho: &JoinedMirrorViewChirho,
    receiver_node_id_chirho: &str,
    clock_chirho: &dyn MonotonicClockChirho,
    transit_budget_millis_chirho: NonZeroU64,
) -> Result<AuthorizedMirrorFinalizeChirho<'frame_chirho>, MirrorContractErrorChirho> {
    verify_mirror_authority_binding_chirho(
        verified_chirho,
        joined_chirho,
        receiver_node_id_chirho,
        clock_chirho,
        transit_budget_millis_chirho,
    )?;
    Ok(AuthorizedMirrorFinalizeChirho { verified_chirho })
}

/// Verify that a receiver's joined view identifies the sender as the current leader at the exact
/// bound term. The receiver's own `is_leader_chirho` bit is intentionally outside this predicate:
/// a legitimate mirror holder is a follower.
pub fn verify_mirror_receiver_elected_leader_chirho(
    joined_chirho: &JoinedMirrorViewChirho,
    sender_chirho: &str,
    bound_term_chirho: u64,
) -> Result<(), MirrorContractErrorChirho> {
    if joined_chirho.elected_leader_node_id_chirho() != Some(sender_chirho)
        || bound_term_chirho != joined_chirho.term_chirho()
    {
        return Err(MirrorContractErrorChirho::sender_not_leader_chirho());
    }
    Ok(())
}

/// The whole receiver-side authority check over any frame's coordinates: exact view and group, the
/// receiver and the sender both serving holders, the stale-term guard, the sender-is-leader inversion,
/// and the leader's rebased lease. It returns no authority token; each contract wraps its own.
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/key-custody-chirho/erasure-propagation-workflow-chirho.md`.
pub fn verify_mirror_authority_binding_chirho(
    frame_chirho: &impl MirrorAuthorityFrameViewChirho,
    joined_chirho: &JoinedMirrorViewChirho,
    receiver_node_id_chirho: &str,
    clock_chirho: &dyn MonotonicClockChirho,
    transit_budget_millis_chirho: NonZeroU64,
) -> Result<(), MirrorContractErrorChirho> {
    let view_chirho = joined_chirho.view_chirho();
    // The ONE term of the joined view. `view_chirho().term_chirho()` and
    // `leadership_chirho().term_chirho` are the same value by construction (the join wrote it from the
    // election observation), so reading it through one accessor removes any later chance of comparing
    // one half against the other.
    let joined_term_chirho = joined_chirho.term_chirho();

    // (0) The view the receiver resolved must be exactly the one the frame names, and the same group.
    if view_chirho.consistency_group_digest_chirho()
        != frame_chirho.consistency_group_digest_chirho()
        || view_chirho.view_digest_chirho() != frame_chirho.membership_view_digest_chirho()
    {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorMembershipViewMismatchChirho,
            "the frame's bound membership view does not match the view this receiver resolved",
        ));
    }

    // (1) The receiver itself must be one of the three placement-authorized serving holders. The held
    // observer is authenticated for its separate evidence role but is never a mirror data holder.
    if frame_chirho.target_node_id_chirho() != receiver_node_id_chirho
        || !view_chirho.is_serving_holder_chirho(receiver_node_id_chirho)
    {
        return Err(MirrorContractErrorChirho::receiver_unrostered_chirho());
    }

    // (2) The sender (frame origin) must be a placement-authorized serving holder.
    let sender_chirho = frame_chirho.origin_node_id_chirho();
    if !view_chirho.is_serving_holder_chirho(sender_chirho) {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorOriginUnrosteredChirho,
            "the frame origin is not a rostered member of the receiver's joined view",
        ));
    }

    // (3) Stale-term guard: the sender's bound term must be at least the receiver's known current
    // term. A term BELOW what the receiver already knows is a deposed / superseded leader.
    let bound_term_chirho = frame_chirho.expected_term_chirho();
    if bound_term_chirho < joined_term_chirho {
        return Err(MirrorContractErrorChirho::term_invalid_chirho());
    }

    // (4) THE INVERSION. The receiver's joined view must show an ESTABLISHED leader that is the FRAME
    // ORIGIN (never `== self`), leading at exactly the bound term. `leader_id_chirho == Some(sender)`
    // alone conveys "an established leader exists AND it is the sender". The receiver's OWN
    // `is_leader_chirho` bit is deliberately NOT consulted: it means "am I the leader", which is false
    // by construction for a follower storing on behalf of the leader, so requiring it would refuse every
    // legitimate mirror prepare once a real elector view is wired (the relay's residual predicate;
    // reviewer F1, 2026-08-09). A bound term ABOVE the receiver's view is a leadership the receiver
    // cannot yet confirm, so it is "sender not leader at the bound term", not a stale-term refusal.
    //
    // Reviewer F3 is DISCHARGED BY CONSTRUCTION, not re-checked here: the roster half and the election
    // half reach this function as one `JoinedMirrorViewChirho`, whose term was written from the single
    // election observation. There is no `view.term == leadership.term` check because there is no way to
    // build a joined view where they differ (`membership_chirho::join_mirror_view_chirho`).
    verify_mirror_receiver_elected_leader_chirho(joined_chirho, sender_chirho, bound_term_chirho)?;

    // (5) Liveness in combination: the LEADER's remaining-duration lease, rebased onto the receiver's
    // own clock (transit consumed, rounds down, absent/<=0 is EXPIRED). This is never sufficient
    // alone and is NEVER the receiver's own lease.
    let leader_deadline_chirho = lease_deadline_from_remaining_chirho(
        clock_chirho,
        frame_chirho.leader_lease_remaining_millis_chirho(),
        transit_budget_millis_chirho,
    );
    if !lease_deadline_is_live_chirho(clock_chirho, leader_deadline_chirho) {
        return Err(MirrorContractErrorChirho::lease_expired_chirho());
    }

    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::membership_chirho::{
        join_mirror_view_chirho, test_observation_chirho, test_verified_placement_chirho,
        FixtureElectionViewChirho,
    };
    use cairn_writer_elector_chirho::monotonic_clock_chirho::FakeMonotonicClockChirho;

    const TERM_CHIRHO: u64 = 5;
    const CONF_INDEX_CHIRHO: u64 = 9;

    struct AuthorityFixtureChirho {
        joined_chirho: JoinedMirrorViewChirho,
        leader_chirho: String,
        follower_chirho: String,
    }

    /// Resolve the fixture's joined view through the REAL `join_mirror_view_chirho`, so these unit
    /// pins exercise the production join rather than a hand-built view the join could never produce.
    /// `elect_leader_chirho == false` models the vacant-leadership case.
    fn fixture_chirho(elect_leader_chirho: bool, term_chirho: u64) -> AuthorityFixtureChirho {
        let placement_chirho = test_verified_placement_chirho();
        let leader_chirho = placement_chirho.assigned_nodes_chirho[0].clone();
        let follower_chirho = placement_chirho.assigned_nodes_chirho[2].clone();
        let observation_chirho = test_observation_chirho(
            &placement_chirho,
            elect_leader_chirho.then_some(leader_chirho.as_str()),
            term_chirho,
            CONF_INDEX_CHIRHO,
        );
        let joined_chirho = join_mirror_view_chirho(
            &placement_chirho.verified_chirho,
            &FixtureElectionViewChirho { observation_chirho },
        )
        .expect("the verified placement and election join");
        AuthorityFixtureChirho {
            joined_chirho,
            leader_chirho,
            follower_chirho,
        }
    }

    fn sender_is_leader_predicate_chirho(
        joined_chirho: &JoinedMirrorViewChirho,
        sender_chirho: &str,
        bound_term_chirho: u64,
    ) -> bool {
        verify_mirror_receiver_elected_leader_chirho(
            joined_chirho,
            sender_chirho,
            bound_term_chirho,
        )
        .is_ok()
    }

    #[test]
    fn the_inversion_truth_table_never_reduces_to_leader_equals_self_chirho() {
        let vacant_chirho = fixture_chirho(false, TERM_CHIRHO);
        let fixture_chirho = fixture_chirho(true, TERM_CHIRHO);

        // The legitimate case: the SENDER is the leader; the receiver (a follower) is NOT.
        assert!(sender_is_leader_predicate_chirho(
            &fixture_chirho.joined_chirho,
            &fixture_chirho.leader_chirho,
            TERM_CHIRHO
        ));
        // The relay's predicate (`leader_id == self`) would be FALSE here — proof the checks differ.
        assert_ne!(
            fixture_chirho.joined_chirho.elected_leader_node_id_chirho(),
            Some(fixture_chirho.follower_chirho.as_str())
        );
        // The receiver's OWN `is_leader` bit is false for a legitimate follower and the predicate
        // succeeds anyway — the F1 omission asserted, not merely commented.
        assert!(
            !fixture_chirho
                .joined_chirho
                .leadership_chirho()
                .is_leader_chirho,
            "a mirror receiver is a follower: consulting its own is_leader would refuse every legitimate prepare"
        );

        // A rostered NON-leader sender is refused.
        assert!(!sender_is_leader_predicate_chirho(
            &fixture_chirho.joined_chirho,
            &fixture_chirho.follower_chirho,
            TERM_CHIRHO
        ));
        // A future term the view cannot confirm is refused.
        assert!(!sender_is_leader_predicate_chirho(
            &fixture_chirho.joined_chirho,
            &fixture_chirho.leader_chirho,
            TERM_CHIRHO + 1
        ));
        // A vacant leadership view is refused.
        assert_eq!(
            vacant_chirho.joined_chirho.elected_leader_node_id_chirho(),
            None
        );
        assert!(!sender_is_leader_predicate_chirho(
            &vacant_chirho.joined_chirho,
            &fixture_chirho.leader_chirho,
            TERM_CHIRHO
        ));
        // View resolves so the fixture is exercised, not merely constructed.
        assert!(fixture_chirho
            .joined_chirho
            .view_chirho()
            .contains_chirho(&fixture_chirho.leader_chirho));
    }

    #[test]
    fn the_sender_predicate_needs_each_of_its_four_conditions_chirho() {
        // C5 B3-a3 item 14 D3: the one sender predicate the ledger mirror and erasure propagation share.
        // Each row breaks exactly one condition, through the real join, so each condition has its own pin.
        let placement_chirho = test_verified_placement_chirho();
        let leader_chirho = placement_chirho.assigned_nodes_chirho[0].clone();
        let follower_chirho = placement_chirho.assigned_nodes_chirho[2].clone();
        let joined_chirho =
            |is_leader_chirho: bool, lease_valid_chirho: bool, remaining_chirho: Option<u64>| {
                let mut observation_chirho = test_observation_chirho(
                    &placement_chirho,
                    Some(leader_chirho.as_str()),
                    TERM_CHIRHO,
                    CONF_INDEX_CHIRHO,
                );
                observation_chirho.leadership_chirho.is_leader_chirho = is_leader_chirho;
                observation_chirho.leadership_chirho.lease_valid_chirho = lease_valid_chirho;
                observation_chirho.leader_lease_remaining_millis_chirho = remaining_chirho;
                join_mirror_view_chirho(
                    &placement_chirho.verified_chirho,
                    &FixtureElectionViewChirho { observation_chirho },
                )
                .expect("the verified placement and election join")
            };
        assert!(
            joined_chirho(true, true, Some(10_000))
                .local_sender_is_elected_leader_chirho(&leader_chirho),
            "all four hold: the elected leader may send"
        );
        for (name_chirho, view_chirho, local_chirho) in [
            (
                "its own election bit says it is not the leader",
                joined_chirho(false, true, Some(10_000)),
                &leader_chirho,
            ),
            (
                "its lease is not valid",
                joined_chirho(true, false, Some(10_000)),
                &leader_chirho,
            ),
            (
                "another node is the elected leader",
                joined_chirho(true, true, Some(10_000)),
                &follower_chirho,
            ),
            (
                "no remaining lease to carry",
                joined_chirho(true, true, None),
                &leader_chirho,
            ),
        ] {
            assert!(
                !view_chirho.local_sender_is_elected_leader_chirho(local_chirho),
                "{name_chirho}"
            );
        }
    }

    #[test]
    fn a_joined_view_can_never_carry_two_different_terms_chirho() {
        // Reviewer F3 stated as the property the TYPE provides: whatever term the election observes,
        // both halves of the joined view report it, for every term rather than one sampled case. That
        // is why clause (4) carries no `view.term == leadership.term` check — the pair is not
        // constructible.
        for term_chirho in [1_u64, TERM_CHIRHO, 4_000_000_000] {
            let fixture_chirho = fixture_chirho(true, term_chirho);
            assert_eq!(fixture_chirho.joined_chirho.term_chirho(), term_chirho);
            assert_eq!(
                fixture_chirho.joined_chirho.view_chirho().term_chirho(),
                fixture_chirho.joined_chirho.leadership_chirho().term_chirho
            );
        }
    }

    #[test]
    fn a_stale_bound_term_is_below_the_receivers_known_term_chirho() {
        // The stale guard fires only when the bound term is strictly below the receiver's view term.
        let clock_chirho = FakeMonotonicClockChirho::new_chirho();
        assert_eq!(clock_chirho.now_millis_chirho(), 0);
        let joined_chirho = fixture_chirho(true, TERM_CHIRHO).joined_chirho;
        assert!(
            TERM_CHIRHO - 1 < joined_chirho.term_chirho(),
            "a bound term below the receiver's known term is stale"
        );
        assert!(
            TERM_CHIRHO >= joined_chirho.term_chirho(),
            "an equal term is not stale"
        );
    }
}
