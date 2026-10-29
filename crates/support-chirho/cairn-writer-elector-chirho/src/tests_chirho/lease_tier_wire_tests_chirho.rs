// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The advertised lease TIER: that it names the branch which computed `lease_valid_chirho`, that it is
//! DIAGNOSIS rather than validity — an unwarmed and a warmed tier-2 leader are indistinguishable on the
//! wire — and that the authority-relevant path stays the duration, which no tier can influence.

use crate::elector_port_chirho::{LeaseTierChirho, NodeIdChirho, WriterElectorChirho};
use crate::monotonic_clock_chirho::{
    lease_deadline_from_remaining_chirho, FakeMonotonicClockChirho,
};
use crate::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::num::NonZeroU64;

fn group_chirho(name_chirho: &str) -> ConsistencyGroupIdChirho {
    ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: format!("/var/lib/cairn-{name_chirho}-chirho"),
    }
}

/// The tier must name the branch that ACTUALLY ran, for each of the three configurations. If someone
/// reorders the branches in `leadership_chirho` without moving `lease_tier_chirho`, this is the test
/// that says so — and it says which configuration diverged, not merely that something did.
#[test]
fn the_advertised_tier_matches_the_branch_that_computed_validity_chirho() {
    // Tier 3 — no warm-up, no monotonic lease: validity is the raw role bit.
    let raw_group_chirho = group_chirho("tier-raw");
    let raw_chirho = RaftWriterElectorChirho::new_single_node_chirho(
        NodeIdChirho("a".repeat(64)),
        raw_group_chirho.clone(),
    )
    .expect("build a raw-role elector");
    assert_eq!(
        raw_chirho.lease_tier_chirho(),
        LeaseTierChirho::RawRoleChirho,
        "no warm-up and no monotonic lease is the raw role bit (tier 3)"
    );

    // Tier 2 — warm-up only: validity is a TICK COUNT, which does not decay with wall-clock time.
    let warm_group_chirho = group_chirho("tier-warmup");
    let warm_chirho = RaftWriterElectorChirho::new_single_node_chirho(
        NodeIdChirho("b".repeat(64)),
        warm_group_chirho.clone(),
    )
    .expect("build a warm-up elector")
    .with_leadership_warmup_lease_chirho();
    assert_eq!(
        warm_chirho.lease_tier_chirho(),
        LeaseTierChirho::TickWarmupChirho,
        "warm-up without a monotonic lease is tier 2"
    );

    // Tier 1 — monotonic lease: warm-up AND expiry decay. Construction turns warm-up on too, so this
    // also pins the BRANCH ORDER: the monotonic arm must win over the warm-up arm, exactly as
    // `leadership_chirho` tests `monotonic_lease_chirho` first.
    let decay_group_chirho = group_chirho("tier-decay");
    let decay_chirho =
        RaftWriterElectorChirho::new_single_node_with_monotonic_leadership_lease_chirho(
            NodeIdChirho("c".repeat(64)),
            decay_group_chirho.clone(),
            FakeMonotonicClockChirho::new_chirho(),
            1_000,
            5_000,
        )
        .expect("build a monotonic-lease elector");
    assert_eq!(
        decay_chirho.lease_tier_chirho(),
        LeaseTierChirho::MonotonicDecayChirho,
        "a monotonic lease is tier 1 even though construction also sets the warm-up flag"
    );
}

/// A warmed tier-2 leader is lease-valid LOCALLY and still sends no remaining-millis, because the
/// early `?` on `monotonic_lease_chirho` means tiers 2 and 3 can never populate that field.
///
/// **This documents a limit, not a fix.** The local `lease_valid_chirho` is true; the wire cannot say
/// so. See the indistinguishability arm below for why the tier does not rescue it.
///
/// If this ever fails because `lease_remaining_millis_chirho` returned `Some`, that is not a
/// regression — it means tiers 2/3 gained a remaining-duration, and the right response is to re-derive
/// whether the tier is still load-bearing on the wire, not to patch the assertion.
#[test]
fn a_warmed_tier_two_leader_is_lease_valid_while_advertising_no_remaining_millis_chirho() {
    let group_ch_chirho = group_chirho("tier-two-gap");
    let elector_chirho = RaftWriterElectorChirho::new_single_node_chirho(
        NodeIdChirho("d".repeat(64)),
        group_ch_chirho.clone(),
    )
    .expect("build a warm-up elector")
    .with_leadership_warmup_lease_chirho();

    elector_chirho.campaign_chirho().expect("self-elect");
    // Tick well past the election timeout so the warm-up clause is satisfied.
    for _tick_chirho in 0..64 {
        elector_chirho.tick_chirho();
    }

    let leadership_chirho = elector_chirho.leadership_chirho(&group_ch_chirho);
    assert!(
        leadership_chirho.is_leader_chirho,
        "the sole voter holds the role bit"
    );
    assert!(
        leadership_chirho.lease_valid_chirho,
        "a warmed tier-2 leader IS lease-valid LOCALLY — the wire is what cannot say so"
    );

    assert_eq!(
        elector_chirho.current_lease_remaining_millis_chirho(),
        None,
        "tier 2 has no monotonic lease, so remaining-millis is None even when locally lease-valid"
    );

    // The tier tells a receiver WHICH kind of None this is. It does not tell it the predicate passed.
    assert_eq!(
        elector_chirho.lease_tier_chirho(),
        LeaseTierChirho::TickWarmupChirho,
        "the tier distinguishes 'no such concept here' from 'expired' — and nothing more"
    );
}

/// **THE TWO ACCESSORS CARRY NO WARM STATE:** for an unwarmed and a warmed tier-2 leader,
/// `lease_tier_chirho()` and `current_lease_remaining_millis_chirho()` return equal values.
///
/// **Scope, stated because an earlier version of this comment overclaimed it.** This arm witnesses the
/// two ACCESSORS and nothing more. It does not construct, serialize, or decode `LeaderInfoChirho` —
/// this crate has no dependency on the HTTP crate and structurally cannot — so it may not make a claim
/// about the wire. The wire claim belongs to
/// `unwarmed_and_warmed_tier_two_leaders_send_byte_identical_responses_chirho` in
/// `cairn-writer-elector-http-chirho`, which drives the production handler and destructures the
/// complete response. **A witness must not be cited for a verdict wider than it covers.**
///
/// The underlying reason is still worth stating here: `lease_tier_chirho()` is derived from
/// CONFIGURATION alone, so warm state cannot reach it.
///
/// **MIGRATION PATH.** If this reddens, one of the two accessors began carrying warm state. That is a
/// new design and goes to the coordinator before the bytes land — do not patch the assertion. Note it
/// reddening does NOT by itself mean the wire changed, and it staying green does NOT mean the wire is
/// unchanged; only the http-crate arm answers that.
#[test]
fn the_two_lease_accessors_carry_no_warm_state_chirho() {
    // Same node identity for both, so ONLY warm state can differ.
    let node_id_chirho = NodeIdChirho("f".repeat(64));

    let unwarmed_group_chirho = group_chirho("tier-two-unwarmed");
    let unwarmed_chirho = RaftWriterElectorChirho::new_single_node_chirho(
        node_id_chirho.clone(),
        unwarmed_group_chirho.clone(),
    )
    .expect("build an unwarmed tier-2 elector")
    .with_leadership_warmup_lease_chirho();
    unwarmed_chirho.campaign_chirho().expect("self-elect");
    // Deliberately NO ticks: leadership is held but the warm-up clause has not been satisfied.

    let warmed_group_chirho = group_chirho("tier-two-warmed");
    let warmed_chirho = RaftWriterElectorChirho::new_single_node_chirho(
        node_id_chirho.clone(),
        warmed_group_chirho.clone(),
    )
    .expect("build a warmed tier-2 elector")
    .with_leadership_warmup_lease_chirho();
    warmed_chirho.campaign_chirho().expect("self-elect");
    for _tick_chirho in 0..64 {
        warmed_chirho.tick_chirho();
    }

    // Non-vacuity: the two nodes genuinely DIFFER in local validity. Without this the equality below
    // could hold merely because neither is warm, and the test would prove nothing.
    assert!(
        !unwarmed_chirho
            .leadership_chirho(&unwarmed_group_chirho)
            .lease_valid_chirho,
        "the unwarmed node must NOT be locally lease-valid, or this fixture proves nothing"
    );
    assert!(
        warmed_chirho
            .leadership_chirho(&warmed_group_chirho)
            .lease_valid_chirho,
        "the warmed node must be locally lease-valid, or this fixture proves nothing"
    );

    // ...and yet every lease-bearing value that crosses the wire is identical.
    assert_eq!(
        unwarmed_chirho.lease_tier_chirho(),
        warmed_chirho.lease_tier_chirho(),
        "the tier cannot carry warm state — it is derived from configuration alone"
    );
    assert_eq!(
        unwarmed_chirho.current_lease_remaining_millis_chirho(),
        warmed_chirho.current_lease_remaining_millis_chirho(),
        "neither tier-2 node can populate remaining-millis"
    );
    assert_eq!(
        (
            unwarmed_chirho.lease_tier_chirho(),
            unwarmed_chirho.current_lease_remaining_millis_chirho()
        ),
        (LeaseTierChirho::TickWarmupChirho, None),
        "the shared wire pair is TickWarmup + None for BOTH warm states"
    );
}

/// The receiver-side converter is TIER-BLIND and duration-only: it takes no tier and cannot be
/// influenced by one, so a non-monotonic tier can never become authoritative through this path.
///
/// Exercising `UnknownChirho` and `RawRoleChirho` alongside a duration is deliberately the pairing a
/// well-behaved sender never produces — the point is that even if such a pair arrived, the tier
/// changes nothing about the deadline derived from it.
#[test]
fn the_lease_deadline_converter_ignores_the_tier_entirely_chirho() {
    let clock_chirho = FakeMonotonicClockChirho::new_chirho();
    let transit_budget_chirho = NonZeroU64::new(50).expect("nonzero transit budget");

    let baseline_chirho = lease_deadline_from_remaining_chirho(
        clock_chirho.as_ref(),
        Some(4_000),
        transit_budget_chirho,
    );

    for tier_chirho in [
        LeaseTierChirho::UnknownChirho,
        LeaseTierChirho::RawRoleChirho,
        LeaseTierChirho::TickWarmupChirho,
        LeaseTierChirho::MonotonicDecayChirho,
    ] {
        // The converter's signature has no tier parameter at all; this loop states that as behaviour
        // so a future signature change that admits one has to redden something.
        let deadline_chirho = lease_deadline_from_remaining_chirho(
            clock_chirho.as_ref(),
            Some(4_000),
            transit_budget_chirho,
        );
        assert_eq!(
            deadline_chirho, baseline_chirho,
            "tier {tier_chirho:?} must not influence the derived deadline"
        );
    }

    // And the fail-closed direction the tier also cannot rescue: absent duration is EXPIRED whatever
    // the tier claims.
    assert!(
        lease_deadline_from_remaining_chirho(clock_chirho.as_ref(), None, transit_budget_chirho)
            .is_none(),
        "no duration means EXPIRED — no tier value can make it otherwise"
    );
}

/// A tier-1 node populates remaining-millis once warmed, so the two fields agree there. This is the
/// control for the test above: it proves the `None` there is a property of TIER 2, not of the fixture.
#[test]
fn a_warmed_tier_one_leader_advertises_both_a_tier_and_a_remaining_duration_chirho() {
    let group_ch_chirho = group_chirho("tier-one-control");
    let clock_chirho = FakeMonotonicClockChirho::new_chirho();
    let elector_chirho =
        RaftWriterElectorChirho::new_single_node_with_monotonic_leadership_lease_chirho(
            NodeIdChirho("e".repeat(64)),
            group_ch_chirho.clone(),
            clock_chirho.clone(),
            1_000,
            60_000,
        )
        .expect("build a monotonic-lease elector");

    elector_chirho.campaign_chirho().expect("self-elect");
    // Tick to warm the role, advancing the clock past the warm-up window as the ticks refresh it.
    for _tick_chirho in 0..64 {
        elector_chirho.tick_chirho();
        clock_chirho.advance_millis_chirho(50);
    }

    assert_eq!(
        elector_chirho.lease_tier_chirho(),
        LeaseTierChirho::MonotonicDecayChirho,
        "a monotonic-lease node reports tier 1"
    );
    assert!(
        elector_chirho
            .current_lease_remaining_millis_chirho()
            .is_some(),
        "tier 1 DOES populate remaining-millis once warmed — so the None above is tier 2's property"
    );
}
