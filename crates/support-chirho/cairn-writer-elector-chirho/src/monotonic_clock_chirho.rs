// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Time as an injected capability, because reading a clock is an effect like any other.
//!
//! The elector was deliberately clock-free: driven entirely by ticks, so the stateright models can
//! reason over tick sequences and the whole thing stays deterministic under test. Giving it a bare
//! `Instant::now()` would end that, and it would do so in the one way this engine exists to forbid —
//! **ambient authority over time**. Effects here happen through declared capabilities, so the clock
//! arrives as a port and tests hand it a fake.
//!
//! **The contract is MONOTONIC, and that word is load-bearing.** An implementation backed by a wall
//! clock is wrong even when it usually agrees: an NTP step or an operator's `date` command must never
//! be able to EXTEND a lease. Named in the trait so no implementor can satisfy it by accident.
//!
//! Milliseconds from an arbitrary fixed origin, deliberately. The origin is meaningless off this
//! process — monotonic clocks have per-process origins — so a reading is only ever compared with
//! another reading from the SAME clock. Anything crossing a process boundary must travel as a
//! remaining DURATION and be converted against the receiver's own clock on arrival.
//!
//! **And the sender's half, which is not symmetric with the receiver's.** A duration can say how much
//! validity REMAINS; it cannot say validity HAS NOT BEGUN. Every duration on this wire asserts "valid
//! for this long", so a state that is not yet valid — a leader still inside its warm-up — must be sent
//! as ABSENCE, never as a number. There is no encoding of "not begun" in a count of milliseconds.
//! This matters because the receiver CANNOT correct it: every rule below resolves toward LESS time, so
//! they fire on absence, on non-positive, and on transit — and none of them shrinks a large,
//! well-formed value. A correct receiver has no defence against a sender advertising maximal validity.

use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// A monotonic time source. Implementations MUST NOT go backwards and MUST NOT be affected by
/// wall-clock adjustments.
pub trait MonotonicClockChirho: Send + Sync + std::fmt::Debug {
    /// Milliseconds since this clock's own arbitrary origin. Only ever compared with other readings
    /// from the same clock.
    fn now_millis_chirho(&self) -> u64;
}

/// The production clock: `std::time::Instant`, which is monotonic on every supported platform.
#[derive(Debug)]
pub struct SystemMonotonicClockChirho {
    origin_chirho: Instant,
}

impl SystemMonotonicClockChirho {
    pub fn new_chirho() -> Self {
        Self {
            origin_chirho: Instant::now(),
        }
    }
}

impl Default for SystemMonotonicClockChirho {
    fn default() -> Self {
        Self::new_chirho()
    }
}

impl MonotonicClockChirho for SystemMonotonicClockChirho {
    fn now_millis_chirho(&self) -> u64 {
        // `Instant::elapsed` is monotonic and saturating, so this never goes backwards.
        self.origin_chirho.elapsed().as_millis() as u64
    }
}

/// A clock a test drives by hand, so lease expiry is provable without sleeping.
#[derive(Debug, Default)]
pub struct FakeMonotonicClockChirho {
    now_millis_chirho: AtomicU64,
}

impl FakeMonotonicClockChirho {
    pub fn new_chirho() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Move time forward. There is deliberately no way to move it back — a fake that could rewind
    /// would let a test assert behaviour the contract forbids.
    pub fn advance_millis_chirho(&self, millis_chirho: u64) {
        self.now_millis_chirho
            .fetch_add(millis_chirho, Ordering::Release);
    }
}

impl MonotonicClockChirho for FakeMonotonicClockChirho {
    fn now_millis_chirho(&self) -> u64 {
        self.now_millis_chirho.load(Ordering::Acquire)
    }
}

/// Convert a lease remaining-duration that arrived over the wire into a deadline on THIS machine's
/// clock. Call it the moment the value is received; any delay after this point is unaccounted for.
///
/// Returns `None` for "expired", which is the only safe reading of a lease you cannot price. Three
/// rules, and each exists because the alternative silently grants authority that has already lapsed:
///
/// 1. **Transit is already consumed.** The budget is `NonZeroU64` rather than validated at runtime:
///    a zero budget encodes "the message arrived instantly", which is never true and fails in the
///    UNSAFE direction, and it is the easiest value to pass by accident or default-initialisation.
///    Unrepresentable beats validated — a runtime refusal can be reached and handled wrongly, a type
///    cannot be constructed wrongly. Erring short costs availability; erring long hands out an
///    expired lease. Start from [`DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO`] and raise it if your links
///    are slower.
/// 2. **Everything rounds DOWN.** Saturating arithmetic throughout, so any ambiguity resolves toward
///    less remaining time.
/// 3. **Nothing left, or nothing parseable, means EXPIRED** — never "unknown, assume valid".
pub fn lease_deadline_from_remaining_chirho(
    clock_chirho: &dyn MonotonicClockChirho,
    remaining_millis_chirho: Option<u64>,
    transit_budget_millis_chirho: NonZeroU64,
) -> Option<u64> {
    let transit_budget_millis_chirho = transit_budget_millis_chirho.get();
    // An absent or unparseable field is expired, not unknown.
    let remaining_chirho = remaining_millis_chirho?;
    let usable_chirho = remaining_chirho.saturating_sub(transit_budget_millis_chirho);
    if usable_chirho == 0 {
        return None;
    }
    Some(
        clock_chirho
            .now_millis_chirho()
            .saturating_add(usable_chirho),
    )
}

/// A starting transit budget: 250ms, chosen to comfortably exceed intra-continental round trips
/// (the measured Hetzner-Germany to OVH-France path is well inside it) while staying small next to a
/// lease measured in seconds. It is a floor to reason from, not a guarantee — a caller whose links
/// are slower must raise it, because the failure of a too-small budget is a lease that expires early
/// and the failure of a too-large one is authority used after it lapsed.
pub const DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO: NonZeroU64 = NonZeroU64::new(250).unwrap();

/// Whether a converted deadline is still in the future on this machine's clock.
pub fn lease_deadline_is_live_chirho(
    clock_chirho: &dyn MonotonicClockChirho,
    deadline_millis_chirho: Option<u64>,
) -> bool {
    match deadline_millis_chirho {
        Some(deadline_chirho) => clock_chirho.now_millis_chirho() < deadline_chirho,
        None => false,
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn nz_chirho(value_chirho: u64) -> NonZeroU64 {
        NonZeroU64::new(value_chirho).expect("non-zero test budget")
    }

    #[test]
    fn the_system_clock_never_goes_backwards_chirho() {
        let clock_chirho = SystemMonotonicClockChirho::new_chirho();
        let mut previous_chirho = clock_chirho.now_millis_chirho();
        for _sample_chirho in 0..200 {
            let now_chirho = clock_chirho.now_millis_chirho();
            assert!(
                now_chirho >= previous_chirho,
                "a monotonic clock went backwards: {previous_chirho} -> {now_chirho}"
            );
            previous_chirho = now_chirho;
        }
    }

    #[test]
    fn the_fake_clock_only_moves_forward_and_by_exactly_what_was_asked_chirho() {
        let clock_chirho = FakeMonotonicClockChirho::new_chirho();
        assert_eq!(clock_chirho.now_millis_chirho(), 0);
        clock_chirho.advance_millis_chirho(1_500);
        assert_eq!(clock_chirho.now_millis_chirho(), 1_500);
        clock_chirho.advance_millis_chirho(1);
        assert_eq!(
            clock_chirho.now_millis_chirho(),
            1_501,
            "the fake must advance by exactly the amount requested, or lease tests prove nothing"
        );
    }

    #[test]
    fn an_absent_remaining_is_expired_not_unknown_chirho() {
        let clock_chirho = FakeMonotonicClockChirho::new_chirho();
        assert_eq!(
            lease_deadline_from_remaining_chirho(clock_chirho.as_ref(), None, nz_chirho(50)),
            None,
            "a lease you cannot price must read as EXPIRED; assuming valid is how expired authority \
             gets used"
        );
        assert!(!lease_deadline_is_live_chirho(clock_chirho.as_ref(), None));
    }

    #[test]
    fn transit_is_treated_as_already_consumed_chirho() {
        let clock_chirho = FakeMonotonicClockChirho::new_chirho();
        clock_chirho.advance_millis_chirho(10_000);
        let deadline_chirho =
            lease_deadline_from_remaining_chirho(clock_chirho.as_ref(), Some(500), nz_chirho(200));
        assert_eq!(
            deadline_chirho,
            Some(10_300),
            "the transit budget must be subtracted, not assumed zero -- erring short costs \
             availability, erring long hands out a lease that already lapsed"
        );
    }

    #[test]
    fn a_remaining_smaller_than_transit_is_expired_chirho() {
        let clock_chirho = FakeMonotonicClockChirho::new_chirho();
        clock_chirho.advance_millis_chirho(5_000);
        assert_eq!(
            lease_deadline_from_remaining_chirho(clock_chirho.as_ref(), Some(100), nz_chirho(200)),
            None,
            "if transit could have consumed the whole lease, it is expired"
        );
        assert_eq!(
            lease_deadline_from_remaining_chirho(clock_chirho.as_ref(), Some(0), nz_chirho(1)),
            None,
            "zero remaining is expired, not a zero-length valid lease"
        );
    }

    #[test]
    fn a_converted_deadline_expires_on_the_receivers_own_clock_chirho() {
        let clock_chirho = FakeMonotonicClockChirho::new_chirho();
        let deadline_chirho = lease_deadline_from_remaining_chirho(
            clock_chirho.as_ref(),
            Some(1_000),
            nz_chirho(100),
        );
        assert!(lease_deadline_is_live_chirho(
            clock_chirho.as_ref(),
            deadline_chirho
        ));
        clock_chirho.advance_millis_chirho(899);
        assert!(
            lease_deadline_is_live_chirho(clock_chirho.as_ref(), deadline_chirho),
            "still inside the usable window"
        );
        clock_chirho.advance_millis_chirho(1);
        assert!(
            !lease_deadline_is_live_chirho(clock_chirho.as_ref(), deadline_chirho),
            "and it lapses on the RECEIVER's clock, with nobody notifying it"
        );
    }
}

#[cfg(test)]
mod wire_absence_tests_chirho {
    use super::*;

    /// (c) from the review: check what the DESERIALISER does with a missing lease field, because if
    /// absence can ever produce a permissive value that is a bug independent of any format change.
    ///
    /// Serde maps a missing `Option` field to `None`, and `None` is expired — so an old sender that
    /// omits the field, or a truncated body, reads as NO LEASE rather than as a valid one. Pinned
    /// here rather than assumed, since "default-to-true on a lease field is catastrophic" and the
    /// distance between `None`-is-expired and `None`-is-unknown is one careless `unwrap_or(true)`.
    #[derive(serde::Deserialize)]
    struct LeaseCarryingBodyChirho {
        #[allow(dead_code)]
        term_chirho: u64,
        lease_remaining_millis_chirho: Option<u64>,
    }

    #[test]
    fn a_body_missing_the_lease_field_reads_as_expired_chirho() {
        let body_chirho: LeaseCarryingBodyChirho =
            serde_json::from_str(r#"{"term_chirho": 7}"#).expect("a body without the lease field");
        assert_eq!(
            body_chirho.lease_remaining_millis_chirho, None,
            "a missing lease field must deserialise to None"
        );
        let clock_chirho = FakeMonotonicClockChirho::new_chirho();
        assert_eq!(
            lease_deadline_from_remaining_chirho(
                clock_chirho.as_ref(),
                body_chirho.lease_remaining_millis_chirho,
                DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO
            ),
            None,
            "and None must mean EXPIRED -- an old sender that omits the field must not be read as \
             holding a valid lease"
        );
    }

    #[test]
    fn an_explicit_null_also_reads_as_expired_chirho() {
        let body_chirho: LeaseCarryingBodyChirho =
            serde_json::from_str(r#"{"term_chirho": 7, "lease_remaining_millis_chirho": null}"#)
                .expect("a body with an explicit null");
        let clock_chirho = FakeMonotonicClockChirho::new_chirho();
        assert!(!lease_deadline_is_live_chirho(
            clock_chirho.as_ref(),
            lease_deadline_from_remaining_chirho(
                clock_chirho.as_ref(),
                body_chirho.lease_remaining_millis_chirho,
                DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO
            )
        ));
    }
}
