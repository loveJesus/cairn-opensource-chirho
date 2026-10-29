// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Wire compatibility for the leader-discovery answer: an older node's response — which carries no
//! lease tier at all — must decode and must read as the value licensing the LEAST trust; and the
//! response an UNWARMED tier-2 leader sends is byte-identical to a warmed one's, proved through the
//! production handler rather than through the accessors behind it.

use crate::driver_chirho::RaftDriverChirho;
use crate::{get_leader_handler_chirho, LeaderInfoChirho, LeaseTierChirho};
use axum::extract::State;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::sync::Arc;
use std::time::Duration;

/// The live-cluster property. Nodes are running the previous format, whose `/leader-chirho` response
/// has no `lease_tier_chirho` key. A new client must decode that response rather than erroring, and
/// must read it as UNKNOWN — never as a tier it guessed on the node's behalf.
///
/// This is the direction that matters: `serde` rejects a missing field for a non-`Option`, non-default
/// field, so without `#[serde(default)]` this exact byte string is a hard decode failure against every
/// node that has not yet been updated.
#[test]
fn an_older_nodes_response_without_a_tier_decodes_as_unknown_chirho() {
    // Byte-for-byte the shape a node on the previous format emits: four fields, no tier.
    let older_response_chirho = r#"{
        "leader_node_id_chirho": "aaaa",
        "is_local_leader_chirho": true,
        "term_chirho": 7,
        "lease_remaining_millis_chirho": 4000
    }"#;

    let decoded_chirho: LeaderInfoChirho =
        serde_json::from_str(older_response_chirho).expect("an older node's response must decode");

    assert_eq!(
        decoded_chirho.lease_tier_chirho,
        LeaseTierChirho::UnknownChirho,
        "a node that named no tier must read as UNKNOWN, not as a tier we invented for it"
    );
    // The rest of the answer survives intact — this is additive, not a reinterpretation.
    assert_eq!(decoded_chirho.term_chirho, 7);
    assert_eq!(decoded_chirho.lease_remaining_millis_chirho, Some(4000));
    assert!(decoded_chirho.is_local_leader_chirho);
}

/// `UnknownChirho` must be what `Default` yields, because that is the value `#[serde(default)]`
/// installs. A future edit that reorders the enum or moves `#[default]` to a real tier would silently
/// upgrade every silent node to a trust level it never claimed; this is the test that stops it.
#[test]
fn the_default_tier_is_the_one_that_licenses_no_trust_chirho() {
    assert_eq!(
        LeaseTierChirho::default(),
        LeaseTierChirho::UnknownChirho,
        "the default must be UNKNOWN — every other variant licenses more trust than silence deserves"
    );
    assert_ne!(LeaseTierChirho::default(), LeaseTierChirho::RawRoleChirho);
    assert_ne!(
        LeaseTierChirho::default(),
        LeaseTierChirho::TickWarmupChirho
    );
    assert_ne!(
        LeaseTierChirho::default(),
        LeaseTierChirho::MonotonicDecayChirho
    );
}

/// A tier survives the round trip unchanged, for every variant. The tier is only useful if it arrives
/// meaning what it left meaning — which is exactly the property the lease BOOLEAN cannot have, and the
/// reason the tier is safe to serialise while the boolean is not.
#[test]
fn every_tier_round_trips_unchanged_chirho() {
    for tier_chirho in [
        LeaseTierChirho::UnknownChirho,
        LeaseTierChirho::MonotonicDecayChirho,
        LeaseTierChirho::TickWarmupChirho,
        LeaseTierChirho::RawRoleChirho,
    ] {
        let info_chirho = LeaderInfoChirho {
            leader_node_id_chirho: Some("bbbb".to_string()),
            is_local_leader_chirho: false,
            term_chirho: 3,
            lease_remaining_millis_chirho: None,
            lease_tier_chirho: tier_chirho,
        };
        let encoded_chirho = serde_json::to_string(&info_chirho).expect("encode leader info");
        let decoded_chirho: LeaderInfoChirho =
            serde_json::from_str(&encoded_chirho).expect("decode leader info");
        assert_eq!(
            decoded_chirho.lease_tier_chirho, tier_chirho,
            "tier {tier_chirho:?} must survive the wire unchanged"
        );
    }
}

/// An older node that is ALSO lease-expired decodes to the same fail-closed reading as an older node
/// that is healthy: unknown tier, and a `None` remaining. Neither is readable as valid, which is the
/// correct outcome — the point of the tier is to stop a *new* node's `None` from being ambiguous, not
/// to rescue trust in nodes that never reported one.
#[test]
fn an_older_node_with_no_lease_is_still_unknown_rather_than_a_tier_chirho() {
    let older_expired_chirho = r#"{
        "leader_node_id_chirho": null,
        "is_local_leader_chirho": false,
        "term_chirho": 0,
        "lease_remaining_millis_chirho": null
    }"#;

    let decoded_chirho: LeaderInfoChirho =
        serde_json::from_str(older_expired_chirho).expect("decode an older node with no lease");

    assert_eq!(
        decoded_chirho.lease_tier_chirho,
        LeaseTierChirho::UnknownChirho
    );
    assert_eq!(decoded_chirho.lease_remaining_millis_chirho, None);
    assert_eq!(decoded_chirho.leader_node_id_chirho, None);
}

/// Build a tier-2 (warm-up, no monotonic lease) single-node elector that has self-elected, ticking it
/// `ticks_chirho` times. Zero ticks leaves it UNWARMED; 64 warms it well past the election timeout.
fn tier_two_leader_chirho(
    node_id_chirho: &NodeIdChirho,
    group_name_chirho: &str,
    ticks_chirho: usize,
) -> Arc<RaftWriterElectorChirho> {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: format!("/var/lib/cairn-{group_name_chirho}-chirho"),
    };
    let elector_chirho = Arc::new(
        RaftWriterElectorChirho::new_single_node_chirho(node_id_chirho.clone(), group_chirho)
            .expect("build a tier-2 elector")
            .with_leadership_warmup_lease_chirho(),
    );
    elector_chirho.campaign_chirho().expect("self-elect");
    for _tick_chirho in 0..ticks_chirho {
        elector_chirho.tick_chirho();
    }
    elector_chirho
}

/// Drive the PRODUCTION handler and return the response it actually builds.
fn leader_response_chirho(elector_chirho: Arc<RaftWriterElectorChirho>) -> LeaderInfoChirho {
    let driver_chirho = Arc::new(
        // One second: inside the bounded delivery window. `from_secs(6)` is REFUSED by the driver —
        // `async_driver_election_chirho.rs` asserts that as an error, not as a usable example.
        RaftDriverChirho::new_chirho(elector_chirho, Vec::new(), Duration::from_secs(1))
            .expect("build a driver over the elector"),
    );
    let runtime_chirho = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("build a current-thread runtime");
    runtime_chirho
        .block_on(get_leader_handler_chirho(State(driver_chirho)))
        .0
}

/// **THE WIRE-LEVEL LIMIT: an unwarmed tier-2 leader and a warmed one send byte-identical responses.**
///
/// This is the arm that may carry that claim, because it goes through the production
/// `LeaderInfoChirho` construction path — the handler itself — rather than comparing the accessors
/// behind it. An accessor-level comparison cannot witness this: a future warm-state field added to the
/// response or to the handler would leave it green while the wire changed underneath.
///
/// **Complete-schema coverage is enforced by the COMPILER, not by an assertion.** Both responses are
/// destructured with an exhaustive pattern and no `..`, so adding any field to `LeaderInfoChirho`
/// fails to compile here. A runtime assertion could not do that — it would silently keep passing while
/// ignoring the new field.
///
/// **MIGRATION PATH — read before "fixing" a failure here.** If this reddens, nobody broke anything:
/// someone ADDED warm-state to the wire. That is a new design a receiver could begin gating on, and it
/// goes to the coordinator as a proposal before the bytes land. Do not patch the assertion to match;
/// retarget it deliberately, or delete it in the commit that reviews the new signal. If instead it
/// fails to COMPILE, a field was added to the response — decide whether it carries warm state, then
/// extend the pattern.
#[test]
fn unwarmed_and_warmed_tier_two_leaders_send_byte_identical_responses_chirho() {
    // Same identity for both, so warm state is the only thing that could differ.
    let node_id_chirho = NodeIdChirho("f".repeat(64));
    let unwarmed_elector_chirho = tier_two_leader_chirho(&node_id_chirho, "wire-unwarmed", 0);
    let warmed_elector_chirho = tier_two_leader_chirho(&node_id_chirho, "wire-warmed", 64);

    // NON-VACUITY, asserted BEFORE transport: the two nodes genuinely differ in local validity. Without
    // this the byte equality below could hold merely because neither is warm, and would prove nothing.
    assert!(
        !unwarmed_elector_chirho
            .current_leadership_chirho()
            .lease_valid_chirho,
        "the unwarmed node must NOT be locally lease-valid, or this fixture proves nothing"
    );
    assert!(
        warmed_elector_chirho
            .current_leadership_chirho()
            .lease_valid_chirho,
        "the warmed node must be locally lease-valid, or this fixture proves nothing"
    );

    let unwarmed_chirho = leader_response_chirho(unwarmed_elector_chirho);
    let warmed_chirho = leader_response_chirho(warmed_elector_chirho);

    // Exhaustive destructure, no `..`: a new response field breaks THIS LINE at compile time.
    let LeaderInfoChirho {
        leader_node_id_chirho: unwarmed_leader_chirho,
        is_local_leader_chirho: unwarmed_is_local_chirho,
        term_chirho: unwarmed_term_chirho,
        lease_remaining_millis_chirho: unwarmed_remaining_chirho,
        lease_tier_chirho: unwarmed_tier_chirho,
    } = &unwarmed_chirho;
    let LeaderInfoChirho {
        leader_node_id_chirho: warmed_leader_chirho,
        is_local_leader_chirho: warmed_is_local_chirho,
        term_chirho: warmed_term_chirho,
        lease_remaining_millis_chirho: warmed_remaining_chirho,
        lease_tier_chirho: warmed_tier_chirho,
    } = &warmed_chirho;

    assert_eq!(
        unwarmed_leader_chirho, warmed_leader_chirho,
        "same node identity on both sides of the comparison"
    );
    assert_eq!(unwarmed_term_chirho, warmed_term_chirho, "same term");
    assert_eq!(
        unwarmed_is_local_chirho, warmed_is_local_chirho,
        "both answer as the local leader"
    );
    assert_eq!(
        unwarmed_tier_chirho, warmed_tier_chirho,
        "the tier cannot carry warm state — it is derived from configuration alone"
    );
    assert_eq!(
        unwarmed_remaining_chirho, warmed_remaining_chirho,
        "neither tier-2 node can populate remaining-millis"
    );
    assert_eq!(
        (*unwarmed_tier_chirho, *unwarmed_remaining_chirho),
        (LeaseTierChirho::TickWarmupChirho, None),
        "the shared wire pair is TickWarmup + None for BOTH warm states"
    );

    // The claim itself, over the whole serialized response.
    let unwarmed_bytes_chirho =
        serde_json::to_string(&unwarmed_chirho).expect("serialize the unwarmed response");
    let warmed_bytes_chirho =
        serde_json::to_string(&warmed_chirho).expect("serialize the warmed response");
    assert_eq!(
        unwarmed_bytes_chirho, warmed_bytes_chirho,
        "an unwarmed and a warmed tier-2 leader are indistinguishable to any receiver"
    );
}
