// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Replay and rewind are caught separately, and every non-fresh verdict freezes BOTH directions.

use super::*;

fn stamp_chirho(hlc_millis_chirho: u64, sequence_chirho: u64) -> MeasurementStampChirho {
    MeasurementStampChirho {
        hlc_millis_chirho,
        sequence_chirho,
    }
}

#[test]
fn a_strictly_newer_stamp_is_fresh_and_unfreezes_both_directions_chirho() {
    let verdict_chirho =
        classify_measurement_chirho(Some(stamp_chirho(1_000, 7)), stamp_chirho(1_001, 8));
    assert_eq!(verdict_chirho, MeasurementVerdictChirho::FreshChirho);
    let posture_chirho = posture_for_verdict_chirho(verdict_chirho);
    assert!(posture_chirho.scale_out_allowed_chirho());
    assert!(posture_chirho.scale_in_allowed_chirho());
    assert!(!posture_chirho.is_frozen_chirho());
}

#[test]
fn a_first_measurement_is_fresh_because_it_contradicts_nothing_chirho() {
    let verdict_chirho = classify_measurement_chirho(None, stamp_chirho(0, 0));
    assert_eq!(verdict_chirho, MeasurementVerdictChirho::FreshChirho);
}

#[test]
fn a_repeated_sequence_is_a_replay_not_merely_stale_chirho() {
    // Re-presenting the SAME signed measurement must not count as new information, even though its
    // clock has not gone backwards. Equality is the case an off-by-one would let through.
    let verdict_chirho =
        classify_measurement_chirho(Some(stamp_chirho(1_000, 7)), stamp_chirho(9_999, 7));
    assert_eq!(
        verdict_chirho,
        MeasurementVerdictChirho::ReplayedChirho {
            last_sequence_chirho: 7,
            offered_sequence_chirho: 7,
        },
        "an equal sequence is a replay however new the clock claims to be"
    );
}

#[test]
fn a_rewound_sequence_is_a_replay_chirho() {
    let verdict_chirho =
        classify_measurement_chirho(Some(stamp_chirho(1_000, 7)), stamp_chirho(1_001, 3));
    assert_eq!(
        verdict_chirho,
        MeasurementVerdictChirho::ReplayedChirho {
            last_sequence_chirho: 7,
            offered_sequence_chirho: 3,
        }
    );
}

#[test]
fn a_rewound_clock_with_a_fresh_sequence_is_still_refused_chirho() {
    // THE CASE THE SEQUENCE ALONE WOULD ACCEPT. The sequence advanced honestly, so a monotone-seq
    // check on its own says fresh; only the HLC comparison catches it. This is why both are checked
    // rather than one standing in for the other.
    let verdict_chirho =
        classify_measurement_chirho(Some(stamp_chirho(5_000, 7)), stamp_chirho(4_999, 8));
    assert_eq!(
        verdict_chirho,
        MeasurementVerdictChirho::RewoundClockChirho {
            last_hlc_millis_chirho: 5_000,
            offered_hlc_millis_chirho: 4_999,
        }
    );
}

#[test]
fn an_equal_clock_with_an_advancing_sequence_is_fresh_chirho() {
    // Two measurements inside the same millisecond are ordinary; the sequence orders them.
    let verdict_chirho =
        classify_measurement_chirho(Some(stamp_chirho(5_000, 7)), stamp_chirho(5_000, 8));
    assert_eq!(verdict_chirho, MeasurementVerdictChirho::FreshChirho);
}

#[test]
fn every_non_fresh_verdict_freezes_scale_out_and_scale_in_together_chirho() {
    // THE PROPERTY THE CRITERION IS ABOUT. Freezing only scale-out is the tempting half-measure —
    // it stops placing new work on a node you cannot see. But scale-in reads the SAME untrusted
    // number to decide a node is underused, so a replayed low-usage measurement would drain a busy
    // node or retire one still holding work. Both must stop together.
    let last_chirho = Some(stamp_chirho(5_000, 7));
    for offered_chirho in [
        stamp_chirho(9_999, 7), // replay by equal sequence
        stamp_chirho(9_999, 1), // replay by rewound sequence
        stamp_chirho(4_999, 8), // rewound clock
    ] {
        let verdict_chirho = classify_measurement_chirho(last_chirho, offered_chirho);
        assert!(
            !verdict_chirho.is_fresh_chirho(),
            "fixture must not be fresh: {verdict_chirho:?}"
        );
        let posture_chirho = posture_for_verdict_chirho(verdict_chirho);
        assert!(
            posture_chirho.is_frozen_chirho(),
            "{verdict_chirho:?} must freeze BOTH directions, got out={} in={}",
            posture_chirho.scale_out_allowed_chirho(),
            posture_chirho.scale_in_allowed_chirho()
        );
    }
}

#[test]
fn the_two_flags_cannot_be_set_apart_because_only_one_constructor_exists_chirho() {
    // Structural, not incidental: `ScalingPostureChirho`'s fields are private and
    // `posture_for_verdict_chirho` is the only way to build one, so a caller cannot assemble a
    // half-frozen posture. This test documents the invariant and fails loudly if a future edit adds
    // a public constructor whose flags disagree.
    for verdict_chirho in [
        MeasurementVerdictChirho::FreshChirho,
        MeasurementVerdictChirho::ReplayedChirho {
            last_sequence_chirho: 7,
            offered_sequence_chirho: 7,
        },
        MeasurementVerdictChirho::RewoundClockChirho {
            last_hlc_millis_chirho: 5_000,
            offered_hlc_millis_chirho: 4_999,
        },
    ] {
        let posture_chirho = posture_for_verdict_chirho(verdict_chirho);
        assert_eq!(
            posture_chirho.scale_out_allowed_chirho(),
            posture_chirho.scale_in_allowed_chirho(),
            "the two directions must always agree: {verdict_chirho:?}"
        );
    }
}
