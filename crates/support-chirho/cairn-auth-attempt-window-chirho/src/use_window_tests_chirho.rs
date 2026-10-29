// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The use window's count against today's rule, written out as `oauth_chirho` writes it: the same app, `at_ms >= now -
//! window` with no upper bound, and the same principal OR the same device, a use counted once.

use super::*;

struct TestUseChirho {
    app_chirho: &'static str,
    principal_chirho: &'static str,
    device_chirho: Option<&'static str>,
    at_ms_chirho: u64,
}

impl UseRecordChirho for TestUseChirho {
    fn app_chirho(&self) -> &str {
        self.app_chirho
    }
    fn principal_chirho(&self) -> &str {
        self.principal_chirho
    }
    fn device_chirho(&self) -> Option<&str> {
        self.device_chirho
    }
    fn at_ms_chirho(&self) -> u64 {
        self.at_ms_chirho
    }
}

/// Today's rule, verbatim in shape: one `filter().count()` over every use.
fn todays_count_chirho(
    uses_chirho: &[TestUseChirho],
    key_chirho: &UseRateKeyChirho<'_>,
    now_ms_chirho: u64,
) -> u64 {
    let window_start_chirho = now_ms_chirho.saturating_sub(key_chirho.window_ms_chirho);
    uses_chirho
        .iter()
        .filter(|use_chirho| {
            use_chirho.app_chirho == key_chirho.app_chirho
                && use_chirho.at_ms_chirho >= window_start_chirho
                && (use_chirho.principal_chirho == key_chirho.principal_chirho
                    || key_chirho.device_chirho.is_some_and(|device_chirho| {
                        use_chirho.device_chirho == Some(device_chirho)
                    }))
        })
        .count() as u64
}

struct RngChirho(u64);

impl RngChirho {
    fn below_chirho(&mut self, bound_chirho: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % bound_chirho
    }
}

const APPS_CHIRHO: [&str; 2] = ["app-a", "app-b"];
const PRINCIPALS_CHIRHO: [&str; 3] = ["p0", "p1", "p2"];
const DEVICES_CHIRHO: [Option<&str>; 4] = [None, Some("d0"), Some("d1"), Some("d2")];
const WINDOWS_CHIRHO: [u64; 3] = [1_000, 60_000, 3_600_000];

/// THE EQUIVALENCE ORACLE: random uses (devices absent and present, uses after `now`), random keys and windows, and a
/// prune at the view's horizon; the index's EXACT count equals today's count for every key whose window starts at or
/// above the cutoff. The coverage control proves the both-buckets case (where a plain sum would double-count) was compared.
///
/// MIGRATION PATH: a difference here means a bearer request is decided differently from today; a plain sum shows as
/// the index above today's count.
#[test]
fn the_index_counts_exactly_as_todays_rule_chirho() {
    let mut double_matches_compared_chirho = 0u64;
    let mut decisions_chirho = 0u64;
    for seed_chirho in 1..=24u64 {
        let mut rng_chirho = RngChirho(seed_chirho.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let mut index_chirho = UseWindowIndexChirho::default();
        let mut uses_chirho: Vec<TestUseChirho> = Vec::new();
        let now_ms_chirho = 10_000_000u64;
        for _ in 0..400 {
            let use_chirho = TestUseChirho {
                app_chirho: APPS_CHIRHO[rng_chirho.below_chirho(2) as usize],
                principal_chirho: PRINCIPALS_CHIRHO[rng_chirho.below_chirho(3) as usize],
                device_chirho: DEVICES_CHIRHO[rng_chirho.below_chirho(4) as usize],
                // Mostly the last hour; some older, some after `now`.
                at_ms_chirho: now_ms_chirho + 120_000 - rng_chirho.below_chirho(4_200_000),
            };
            index_chirho.fold_chirho(&use_chirho);
            uses_chirho.push(use_chirho);
        }
        let cutoff_chirho = now_ms_chirho - 3_600_000;
        index_chirho.prune_chirho(cutoff_chirho);
        for app_chirho in APPS_CHIRHO {
            for principal_chirho in PRINCIPALS_CHIRHO {
                for device_chirho in DEVICES_CHIRHO {
                    for window_chirho in WINDOWS_CHIRHO {
                        let key_chirho = UseRateKeyChirho {
                            app_chirho,
                            principal_chirho,
                            device_chirho,
                            window_ms_chirho: window_chirho,
                        };
                        let todays_chirho =
                            todays_count_chirho(&uses_chirho, &key_chirho, now_ms_chirho);
                        assert_eq!(
                            index_chirho.exact_count_chirho(&key_chirho, now_ms_chirho),
                            Some(todays_chirho),
                            "seed {seed_chirho}: {app_chirho} {principal_chirho} {device_chirho:?} {window_chirho}"
                        );
                        decisions_chirho += 1;
                        if device_chirho.is_some()
                            && uses_chirho.iter().any(|use_chirho| {
                                use_chirho.app_chirho == app_chirho
                                    && use_chirho.principal_chirho == principal_chirho
                                    && use_chirho.device_chirho == device_chirho
                                    && use_chirho.at_ms_chirho >= now_ms_chirho - window_chirho
                            })
                        {
                            double_matches_compared_chirho += 1;
                        }
                    }
                }
            }
        }
    }
    assert!(decisions_chirho > 0);
    assert!(
        double_matches_compared_chirho > 0,
        "the oracle never compared a key a use matched by principal AND device"
    );
}

/// The None rule on both sides: a use without a device never matches a device, and a token without one counts its
/// principal bucket alone.
#[test]
fn an_absent_device_never_matches_chirho() {
    let mut index_chirho = UseWindowIndexChirho::default();
    for use_chirho in [
        TestUseChirho {
            app_chirho: "app-a",
            principal_chirho: "p0",
            device_chirho: None,
            at_ms_chirho: 100,
        },
        TestUseChirho {
            app_chirho: "app-a",
            principal_chirho: "p1",
            device_chirho: None,
            at_ms_chirho: 100,
        },
        TestUseChirho {
            app_chirho: "app-a",
            principal_chirho: "p1",
            device_chirho: Some("d0"),
            at_ms_chirho: 100,
        },
    ] {
        index_chirho.fold_chirho(&use_chirho);
    }
    let without_device_chirho = UseRateKeyChirho {
        app_chirho: "app-a",
        principal_chirho: "p0",
        device_chirho: None,
        window_ms_chirho: 1_000,
    };
    assert_eq!(
        index_chirho.count_chirho(&without_device_chirho, 500),
        1,
        "p0's own use only"
    );
    let with_device_chirho = UseRateKeyChirho {
        device_chirho: Some("d0"),
        ..without_device_chirho
    };
    assert_eq!(
        index_chirho.count_chirho(&with_device_chirho, 500),
        2,
        "p0's use and the d0 use, never p1's device-less one"
    );
}

/// Prune drops only uses below the cutoff, from every bucket kind alike.
#[test]
fn prune_keeps_the_window_and_drops_the_rest_chirho() {
    let mut index_chirho = UseWindowIndexChirho::default();
    for at_ms_chirho in [10, 20, 30] {
        index_chirho.fold_chirho(&TestUseChirho {
            app_chirho: "app-a",
            principal_chirho: "p0",
            device_chirho: Some("d0"),
            at_ms_chirho,
        });
    }
    index_chirho.prune_chirho(20);
    let key_chirho = UseRateKeyChirho {
        app_chirho: "app-a",
        principal_chirho: "p9",
        device_chirho: Some("d0"),
        window_ms_chirho: 1_000,
    };
    assert_eq!(
        index_chirho.count_chirho(&key_chirho, 30),
        2,
        "the uses at 20 and 30 remain"
    );
    index_chirho.prune_chirho(31);
    assert_eq!(
        index_chirho.tracked_buckets_chirho(),
        0,
        "empty buckets are dropped"
    );
}

/// The exact count answers only while the window starts inside the retained history: a window reaching below the last
/// prune gets `None`, never a smaller number, and an index never pruned answers for any window.
///
/// MIGRATION PATH: a `Some` below the retained horizon is the defect this exists for. The append door would decide
/// from a count missing pruned uses and could write a use the full verifier refuses forever.
#[test]
fn the_exact_count_answers_only_inside_the_retained_history_chirho() {
    let mut index_chirho = UseWindowIndexChirho::default();
    for at_ms_chirho in [500, 1_500, 2_500] {
        index_chirho.fold_chirho(&TestUseChirho {
            app_chirho: "app-a",
            principal_chirho: "p0",
            device_chirho: None,
            at_ms_chirho,
        });
    }
    let key_chirho = UseRateKeyChirho {
        app_chirho: "app-a",
        principal_chirho: "p0",
        device_chirho: None,
        window_ms_chirho: 2_000,
    };
    assert_eq!(
        index_chirho.exact_count_chirho(&key_chirho, 2_500),
        Some(3),
        "never pruned: exact everywhere"
    );
    index_chirho.prune_chirho(1_000);
    assert_eq!(
        index_chirho.exact_count_chirho(&key_chirho, 3_000),
        Some(2),
        "window starts at the horizon"
    );
    assert_eq!(
        index_chirho.exact_count_chirho(&key_chirho, 2_999),
        None,
        "a window starting below the horizon may miss the pruned use at 500"
    );
    assert_eq!(
        index_chirho.count_chirho(&key_chirho, 2_999),
        2,
        "the plain count is then only a lower bound"
    );
}

/// The clock rule: a step back within the tolerance stays exact with no rebuild; one beyond it asks for the rebuild,
/// and a later, lower `now` never lowers the high-water mark or the retained horizon.
#[test]
fn the_clock_rule_rebuilds_only_beyond_the_tolerance_chirho() {
    let mut index_chirho = UseWindowIndexChirho::default();
    index_chirho.advance_chirho(10_000, 3_000);
    assert!(
        !index_chirho.needs_rebuild_chirho(9_000, 1_000),
        "exactly the tolerance back"
    );
    assert!(
        index_chirho.needs_rebuild_chirho(8_999, 1_000),
        "one past the tolerance"
    );
    index_chirho.advance_chirho(8_000, 3_000);
    assert!(
        index_chirho.needs_rebuild_chirho(8_000, 1_000),
        "the high water stays at 10,000 until a rebuilt index replaces this one"
    );
    let key_chirho = UseRateKeyChirho {
        app_chirho: "app-a",
        principal_chirho: "p0",
        device_chirho: None,
        window_ms_chirho: 1_000,
    };
    assert_eq!(
        index_chirho.exact_count_chirho(&key_chirho, 8_000),
        Some(0),
        "8,000 - 1,000 is the horizon 7,000"
    );
    assert_eq!(
        index_chirho.exact_count_chirho(&key_chirho, 7_999),
        None,
        "the horizon did not move down"
    );
}
