// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Stale or replayed measurement evidence freezes a node's scaling — in BOTH directions.
//!
//! CF8 acceptance, verbatim: *"measured usage is node-signed with HLC and monotone sequence …
//! admission requires configured headroom plus fresh non-divergent measurement, and stale/replayed
//! evidence freezes both scale-out and scale-in for that node."*
//!
//! **Why both directions, when freezing only scale-out sounds safer.** Scale-out is the obvious
//! hazard: placing new work on a node whose real usage you cannot currently see. But scale-in reads
//! the same untrusted number in the other direction — it decides a node is *underused* and moves work
//! off it, or retires it. Acting on a replayed low-usage measurement would drain a node that is
//! actually busy, or retire one still holding work. So a measurement you cannot trust must stop
//! **every** decision that reads it, and this module makes that structural: the posture type is
//! constructed only through [`posture_for_verdict_chirho`], which returns both flags together, so no
//! caller can freeze one direction and leave the other open.
//!
//! **Monotone sequence is the replay defence; HLC is the ordering defence.** They catch different
//! attacks and are checked separately:
//! - A repeated or rewound **sequence** is a replay — the same signed bytes offered twice. Equality
//!   counts: a re-presented measurement is not new information.
//! - A **rewound HLC** with a fresh sequence is a clock anomaly. The sequence alone would accept it,
//!   which is why both are checked rather than one standing in for the other.
//!
//! **"Stale" here means non-advancing or rewound relative to the accepted chain; this module does
//! not measure wall-clock age.** A week-old report whose sequence and HLC advance still classifies
//! fresh here. Authority-bearing admission separately pins an operator-reviewed evidence snapshot;
//! do not infer an age window from this ordering verdict or recompute that external snapshot beside
//! the log it authenticates.
//!
//! Pure: no I/O, no clock, no keys. **Signature verification is the caller's job and is not
//! duplicated here** — this module answers only "is this stamp newer than what I last accepted", and
//! a caller that skips the signature check gets a confident answer about bytes nobody vouched for.

use serde::{Deserialize, Serialize};

/// The ordering coordinates of one node-signed usage measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasurementStampChirho {
    /// Hybrid logical clock reading, in milliseconds.
    pub hlc_millis_chirho: u64,
    /// Per-node monotone sequence; strictly increases for each new measurement.
    pub sequence_chirho: u64,
}

/// What a newly offered stamp is, relative to the last one accepted for that node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeasurementVerdictChirho {
    /// Strictly newer sequence and a non-rewound clock: usable evidence.
    FreshChirho,
    /// The sequence did not advance — the same measurement offered again, or an older one.
    ReplayedChirho {
        last_sequence_chirho: u64,
        offered_sequence_chirho: u64,
    },
    /// The sequence advanced but the clock went backwards.
    RewoundClockChirho {
        last_hlc_millis_chirho: u64,
        offered_hlc_millis_chirho: u64,
    },
}

impl MeasurementVerdictChirho {
    /// Only `FreshChirho` is usable; everything else freezes.
    pub fn is_fresh_chirho(&self) -> bool {
        matches!(self, Self::FreshChirho)
    }
}

/// Whether a node may currently be scaled, in each direction. Constructed only by
/// [`posture_for_verdict_chirho`] so the two flags cannot drift apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScalingPostureChirho {
    scale_out_allowed_chirho: bool,
    scale_in_allowed_chirho: bool,
}

impl ScalingPostureChirho {
    /// May new work be placed on this node?
    pub fn scale_out_allowed_chirho(&self) -> bool {
        self.scale_out_allowed_chirho
    }
    /// May work be drained off, or the node retired?
    pub fn scale_in_allowed_chirho(&self) -> bool {
        self.scale_in_allowed_chirho
    }
    /// Is the node frozen in both directions?
    pub fn is_frozen_chirho(&self) -> bool {
        !self.scale_out_allowed_chirho && !self.scale_in_allowed_chirho
    }
}

/// Classify an offered stamp against the last accepted one. `None` means no measurement has been
/// accepted yet, in which case any stamp is fresh — a node's first measurement has nothing to
/// contradict.
pub fn classify_measurement_chirho(
    last_accepted_chirho: Option<MeasurementStampChirho>,
    offered_chirho: MeasurementStampChirho,
) -> MeasurementVerdictChirho {
    let Some(last_chirho) = last_accepted_chirho else {
        return MeasurementVerdictChirho::FreshChirho;
    };
    // Replay first: a non-advancing sequence is the strongest signal, and reporting it as a clock
    // problem would send an operator to the wrong place.
    if offered_chirho.sequence_chirho <= last_chirho.sequence_chirho {
        return MeasurementVerdictChirho::ReplayedChirho {
            last_sequence_chirho: last_chirho.sequence_chirho,
            offered_sequence_chirho: offered_chirho.sequence_chirho,
        };
    }
    if offered_chirho.hlc_millis_chirho < last_chirho.hlc_millis_chirho {
        return MeasurementVerdictChirho::RewoundClockChirho {
            last_hlc_millis_chirho: last_chirho.hlc_millis_chirho,
            offered_hlc_millis_chirho: offered_chirho.hlc_millis_chirho,
        };
    }
    MeasurementVerdictChirho::FreshChirho
}

/// The scaling posture a verdict implies. Anything other than fresh freezes **both** directions.
/// The posture of a node that has NEVER been measured: frozen in both directions.
///
/// Never having been measured is not the same as having been measured and found fine. Clause 7 says
/// admission requires a FRESH measurement, so the absence of one is not permission — it is the absence
/// of the thing admission requires.
///
/// This exists so callers do not synthesize a fake verdict to obtain a frozen posture. A fabricated
/// `ReplayedChirho { 0, 0 }` produces the right booleans and reports a replay that never happened the
/// moment it reaches a diagnostic.
pub fn never_measured_posture_chirho() -> ScalingPostureChirho {
    ScalingPostureChirho {
        scale_out_allowed_chirho: false,
        scale_in_allowed_chirho: false,
    }
}

pub fn posture_for_verdict_chirho(
    verdict_chirho: MeasurementVerdictChirho,
) -> ScalingPostureChirho {
    let usable_chirho = verdict_chirho.is_fresh_chirho();
    ScalingPostureChirho {
        scale_out_allowed_chirho: usable_chirho,
        scale_in_allowed_chirho: usable_chirho,
    }
}

#[cfg(test)]
#[path = "measurement_freshness_tests_chirho.rs"]
mod measurement_freshness_tests_chirho;
