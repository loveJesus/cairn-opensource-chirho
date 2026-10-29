// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;
use axum::http::HeaderValue;
use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};

fn test_limits_chirho() -> ServedRequestAbuseLimitsChirho {
    ServedRequestAbuseLimitsChirho {
        window_ms_chirho: 1_000,
        actor_max_requests_chirho: 2,
        actor_max_body_bytes_chirho: 10,
        global_max_requests_chirho: 8,
        global_max_body_bytes_chirho: 80,
        actor_bucket_cap_chirho: 16,
        ..ServedRequestAbuseLimitsChirho::default()
    }
}

fn test_inflight_chirho() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(32))
}

fn peer_v4_chirho(last_octet_chirho: u8) -> SocketAddr {
    SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, last_octet_chirho), 443).into()
}

#[test]
fn zero_or_inverted_limits_fail_closed_chirho() {
    let mut limits_chirho = test_limits_chirho();
    limits_chirho.actor_max_requests_chirho = 0;
    assert!(limits_chirho.validate_chirho().is_err());

    let mut limits_chirho = test_limits_chirho();
    limits_chirho.global_max_requests_chirho = 1;
    assert!(limits_chirho.validate_chirho().is_err());
}

#[test]
fn actor_request_and_body_quotas_reopen_only_after_window_chirho() {
    let gate_chirho = ServedRequestAbuseGateChirho::new_chirho(test_limits_chirho()).unwrap();
    let headers_chirho = HeaderMap::new();
    let peer_chirho = Some(peer_v4_chirho(1));
    drop(
        gate_chirho
            .admit_for_test_chirho(
                test_inflight_chirho(),
                peer_chirho,
                &headers_chirho,
                None,
                6,
                0,
            )
            .unwrap(),
    );
    assert!(gate_chirho
        .admit_for_test_chirho(
            test_inflight_chirho(),
            peer_chirho,
            &headers_chirho,
            None,
            5,
            999,
        )
        .is_err());
    drop(
        gate_chirho
            .admit_for_test_chirho(
                test_inflight_chirho(),
                peer_chirho,
                &headers_chirho,
                None,
                5,
                1_000,
            )
            .unwrap(),
    );
}

#[test]
fn principal_quota_survives_network_rotation_chirho() {
    let gate_chirho = ServedRequestAbuseGateChirho::new_chirho(test_limits_chirho()).unwrap();
    let headers_chirho = HeaderMap::new();
    for peer_suffix_chirho in [1, 2] {
        drop(
            gate_chirho
                .admit_for_test_chirho(
                    test_inflight_chirho(),
                    Some(peer_v4_chirho(peer_suffix_chirho)),
                    &headers_chirho,
                    Some("owner/verified-chirho"),
                    1,
                    0,
                )
                .unwrap(),
        );
    }
    assert!(gate_chirho
        .admit_for_test_chirho(
            test_inflight_chirho(),
            Some(peer_v4_chirho(3)),
            &headers_chirho,
            Some("owner/verified-chirho"),
            1,
            0,
        )
        .is_err());
}

#[test]
fn network_quota_survives_principal_rotation_chirho() {
    let gate_chirho = ServedRequestAbuseGateChirho::new_chirho(test_limits_chirho()).unwrap();
    let headers_chirho = HeaderMap::new();
    for principal_chirho in ["owner/a-chirho", "owner/b-chirho"] {
        drop(
            gate_chirho
                .admit_for_test_chirho(
                    test_inflight_chirho(),
                    Some(peer_v4_chirho(4)),
                    &headers_chirho,
                    Some(principal_chirho),
                    1,
                    0,
                )
                .unwrap(),
        );
    }
    assert!(gate_chirho
        .admit_for_test_chirho(
            test_inflight_chirho(),
            Some(peer_v4_chirho(4)),
            &headers_chirho,
            Some("owner/c-chirho"),
            1,
            0,
        )
        .is_err());
}

#[test]
fn global_quota_catches_distributed_networks_chirho() {
    let mut limits_chirho = test_limits_chirho();
    limits_chirho.global_max_requests_chirho = 3;
    let gate_chirho = ServedRequestAbuseGateChirho::new_chirho(limits_chirho).unwrap();
    let headers_chirho = HeaderMap::new();
    for peer_suffix_chirho in [1, 2, 3] {
        drop(
            gate_chirho
                .admit_for_test_chirho(
                    test_inflight_chirho(),
                    Some(peer_v4_chirho(peer_suffix_chirho)),
                    &headers_chirho,
                    None,
                    1,
                    0,
                )
                .unwrap(),
        );
    }
    assert!(gate_chirho
        .admit_for_test_chirho(
            test_inflight_chirho(),
            Some(peer_v4_chirho(4)),
            &headers_chirho,
            None,
            1,
            0,
        )
        .is_err());
}

#[test]
fn client_network_trusts_forwarding_only_from_loopback_chirho() {
    let mut forwarded_one_chirho = HeaderMap::new();
    forwarded_one_chirho.insert(
        X_FORWARDED_FOR_CHIRHO,
        HeaderValue::from_static("203.0.113.7"),
    );
    let mut forwarded_two_chirho = HeaderMap::new();
    forwarded_two_chirho.insert(
        X_FORWARDED_FOR_CHIRHO,
        HeaderValue::from_static("203.0.113.8"),
    );
    let loopback_one_chirho: SocketAddr = "127.0.0.1:1000".parse().unwrap();
    let loopback_two_chirho: SocketAddr = "127.0.0.1:2000".parse().unwrap();
    assert!(served_network_keys_match_for_test_chirho(
        Some(loopback_one_chirho),
        &forwarded_one_chirho,
        Some(loopback_two_chirho),
        &forwarded_one_chirho,
    ));
    assert!(!served_network_keys_match_for_test_chirho(
        Some(loopback_one_chirho),
        &forwarded_one_chirho,
        Some(loopback_two_chirho),
        &forwarded_two_chirho,
    ));
    assert!(!served_network_keys_match_for_test_chirho(
        Some(peer_v4_chirho(1)),
        &forwarded_one_chirho,
        Some(peer_v4_chirho(2)),
        &forwarded_one_chirho,
    ));
    let mut malformed_chirho = HeaderMap::new();
    malformed_chirho.insert(
        X_FORWARDED_FOR_CHIRHO,
        HeaderValue::from_static("not-an-ip-chirho"),
    );
    assert!(served_network_keys_match_for_test_chirho(
        Some(loopback_one_chirho),
        &malformed_chirho,
        Some(loopback_two_chirho),
        &HeaderMap::new(),
    ));
}

#[test]
fn ipv6_networks_group_by_64_and_missing_metadata_is_shared_chirho() {
    let first_chirho: SocketAddr =
        SocketAddrV6::new("2001:db8:1234:5678::1".parse().unwrap(), 443, 0, 0).into();
    let second_chirho: SocketAddr =
        SocketAddrV6::new("2001:db8:1234:5678::ffff".parse().unwrap(), 443, 0, 0).into();
    let headers_chirho = HeaderMap::new();
    assert!(served_network_keys_match_for_test_chirho(
        Some(first_chirho),
        &headers_chirho,
        Some(second_chirho),
        &headers_chirho,
    ));
    assert!(served_network_keys_match_for_test_chirho(
        None,
        &headers_chirho,
        None,
        &headers_chirho,
    ));
}

#[test]
fn actor_bucket_cardinality_never_exceeds_bound_chirho() {
    let mut limits_chirho = test_limits_chirho();
    limits_chirho.actor_bucket_cap_chirho = 2;
    let gate_chirho = ServedRequestAbuseGateChirho::new_chirho(limits_chirho).unwrap();
    let headers_chirho = HeaderMap::new();
    for peer_suffix_chirho in [1, 2] {
        drop(
            gate_chirho
                .admit_for_test_chirho(
                    test_inflight_chirho(),
                    Some(peer_v4_chirho(peer_suffix_chirho)),
                    &headers_chirho,
                    None,
                    1,
                    0,
                )
                .unwrap(),
        );
    }
    assert!(gate_chirho
        .admit_for_test_chirho(
            test_inflight_chirho(),
            Some(peer_v4_chirho(3)),
            &headers_chirho,
            None,
            1,
            0,
        )
        .is_err());
    assert_eq!(gate_chirho.actor_bucket_count_for_test_chirho(), 2);
}

/// R13 Part 8's promise to a client that honours the refusal (PFE #26171, #26172). A client refused at instant T, all of
/// whose charges sit at or before T, is ADMITTED when it retries after exactly the advertised Retry-After: a charge
/// leaves the window at an age equal to the window, and Retry-After is the window rounded UP to whole seconds. A refusal
/// charges nothing, so an impatient client retrying every quarter second is admitted the moment the window clears, never
/// later than the patient one. The retry instant comes from the gate's own Retry-After, so an advertised value shorter
/// than the window reddens here; the 1.5-second window is the case where the rounding matters.
#[test]
fn retry_after_admits_a_patient_client_and_refusals_charge_nothing_chirho() {
    const T_CHIRHO: u64 = 5_000;
    fn admit_chirho(
        gate_chirho: &ServedRequestAbuseGateChirho,
        principal_chirho: &str,
        at_ms_chirho: u64,
    ) -> Result<()> {
        gate_chirho
            .admit_for_test_chirho(
                test_inflight_chirho(),
                Some(peer_v4_chirho(7)),
                &HeaderMap::new(),
                Some(principal_chirho),
                0,
                at_ms_chirho,
            )
            .map(drop)
    }
    fn refused_by_quota_chirho(outcome_chirho: Result<()>) -> bool {
        outcome_chirho
            .is_err_and(|error_chirho| error_chirho.to_string().contains("quota exceeded"))
    }
    for window_ms_chirho in [60_000_u64, 1_500] {
        let limits_chirho = ServedRequestAbuseLimitsChirho {
            window_ms_chirho,
            ..ServedRequestAbuseLimitsChirho::default()
        };
        // Every charge at the one instant T is the worst case: the youngest charge is as young as the refusal.
        let filled_at_t_chirho = |principal_chirho: &str| {
            let gate_chirho = ServedRequestAbuseGateChirho::new_chirho(limits_chirho).unwrap();
            for _ in 0..limits_chirho.actor_max_requests_chirho {
                admit_chirho(&gate_chirho, principal_chirho, T_CHIRHO).unwrap();
            }
            assert!(refused_by_quota_chirho(admit_chirho(
                &gate_chirho,
                principal_chirho,
                T_CHIRHO
            )));
            gate_chirho
        };

        let patient_chirho = filled_at_t_chirho("user/patient-chirho");
        let retry_at_chirho = T_CHIRHO + patient_chirho.retry_after_secs_chirho() * 1_000;
        assert!(
            admit_chirho(&patient_chirho, "user/patient-chirho", retry_at_chirho).is_ok(),
            "window {window_ms_chirho} ms: the first retry after Retry-After must be admitted"
        );

        let impatient_chirho = filled_at_t_chirho("user/impatient-chirho");
        let window_clears_at_chirho = T_CHIRHO + window_ms_chirho;
        let mut at_chirho = T_CHIRHO + 250;
        while at_chirho < window_clears_at_chirho {
            assert!(
                refused_by_quota_chirho(admit_chirho(
                    &impatient_chirho,
                    "user/impatient-chirho",
                    at_chirho
                )),
                "window {window_ms_chirho} ms: an early retry at {at_chirho} must be refused by the quota"
            );
            at_chirho += 250;
        }
        assert!(refused_by_quota_chirho(admit_chirho(
            &impatient_chirho,
            "user/impatient-chirho",
            window_clears_at_chirho - 1
        )));
        assert!(
            admit_chirho(&impatient_chirho, "user/impatient-chirho", window_clears_at_chirho).is_ok(),
            "window {window_ms_chirho} ms: the refusals must have charged nothing, so the window clears on time"
        );
        assert!(window_clears_at_chirho <= retry_at_chirho);
    }
}
