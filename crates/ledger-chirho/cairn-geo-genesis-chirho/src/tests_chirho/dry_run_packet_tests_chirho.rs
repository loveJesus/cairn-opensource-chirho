// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Redaction-safe dry-run packet arms (8.3): the packet is built from a verified plan + its bound
//! custody-presence and config-cross-bind tokens, carries only counts/enums/digests, round-trips, and
//! its bytes contain ZERO forbidden markers; each host-path/bearer/principal/provider/endpoint needle
//! is a planted positive control that fires its own reason; building the packet generates no key and
//! creates no file; and a tampered count/digest/token-binding refuses.

use super::fixtures_chirho::{
    author_custody_attestation_chirho, custody_domain_chirho, derived_pk_chirho,
    member_wireguard_key_chirho, plan_roster_projection_chirho, provision_signer_chirho,
    split_pins_chirho, verified_plan_with_config_projections_chirho, verified_valid_plan_chirho,
    ACCEPTANCE_AUTHORITY_SEED_CHIRHO, CUSTODY_AUTHORITY_SEED_CHIRHO, MEMBER_SEEDS_CHIRHO,
    PLAN_AUTHORITY_SEED_CHIRHO,
};
use crate::dry_run_packet_chirho::{
    scan_forbidden_markers_chirho, DRY_RUN_BEARER_MARKERS_CHIRHO, DRY_RUN_ENDPOINT_MARKERS_CHIRHO,
    DRY_RUN_HOST_PATH_MARKERS_CHIRHO, DRY_RUN_PRINCIPAL_MARKERS_CHIRHO,
    DRY_RUN_PROVIDER_MARKERS_CHIRHO,
};
use crate::error_chirho::{GeoDryRunLeakReasonChirho, GeoGenesisRefusalChirho};
use crate::{
    build_dry_run_packet_chirho, canonical_dry_run_packet_chirho,
    cluster_config_projection_digest_chirho, cross_bind_member_configs_chirho,
    verify_custody_presence_chirho, verify_dry_run_packet_chirho,
    GeoClusterConfigMemberProjectionV1Chirho, GeoClusterConfigProjectionSchemaChirho,
    GeoClusterConfigProjectionSourceV1Chirho, GeoConsistencyGroupDigestChirho,
    GeoEndpointAddressV1Chirho, GeoIpAddressChirho, GeoMemberCustodyPinV1Chirho,
    GeoMemberRoleChirho, GeoOperatorCustodyConfigV1Chirho, GeoOperatorGuardIdentityChirho,
    GeoOperatorGuardRootChirho, GeoPortChirho, GeoRaftIdChirho, GeoSignerRoleChirho,
    VerifiedGenesisConfigCrossBindChirho, VerifiedGenesisCustodyPresenceChirho,
    VerifiedGeoGenesisPlanChirho,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_dir_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let ordinal_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-geo-83-dryrun-{nanos_chirho}-{ordinal_chirho}"
    ))
}

fn temp_guard_root_chirho() -> (GeoOperatorGuardRootChirho, PathBuf) {
    let dir_chirho = unique_temp_dir_chirho();
    std::fs::create_dir_all(&dir_chirho).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir_chirho, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let identity_chirho = GeoOperatorGuardIdentityChirho::new_chirho([77; 32]).unwrap();
    (
        GeoOperatorGuardRootChirho::new_chirho(dir_chirho.clone(), identity_chirho),
        dir_chirho,
    )
}

fn member_pins_chirho() -> Vec<GeoMemberCustodyPinV1Chirho> {
    (0..3usize)
        .map(|index_chirho| {
            let seed_chirho = MEMBER_SEEDS_CHIRHO[index_chirho];
            GeoMemberCustodyPinV1Chirho {
                raft_id_chirho: GeoRaftIdChirho::new_chirho(index_chirho as u64 + 1).unwrap(),
                node_key_chirho: derived_pk_chirho(seed_chirho),
                wireguard_key_chirho: member_wireguard_key_chirho(seed_chirho),
            }
        })
        .collect()
}

fn valid_config_chirho(
    guard_root_chirho: GeoOperatorGuardRootChirho,
) -> GeoOperatorCustodyConfigV1Chirho {
    let custody_signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::CustodyAuthorityChirho,
        CUSTODY_AUTHORITY_SEED_CHIRHO,
    );
    let custody_pin_chirho = custody_signer_chirho.public_key_chirho();
    GeoOperatorCustodyConfigV1Chirho {
        trust_pins_chirho: split_pins_chirho(),
        custody_authority_pin_chirho: custody_pin_chirho,
        roster_projection_chirho: plan_roster_projection_chirho(),
        member_pins_chirho: member_pins_chirho(),
        operator_guard_root_chirho: guard_root_chirho,
        plan_custody_attestation_chirho: author_custody_attestation_chirho(
            &custody_signer_chirho,
            custody_domain_chirho(1),
            derived_pk_chirho(PLAN_AUTHORITY_SEED_CHIRHO),
            custody_pin_chirho,
        ),
        acceptance_custody_attestation_chirho: author_custody_attestation_chirho(
            &custody_signer_chirho,
            custody_domain_chirho(2),
            derived_pk_chirho(ACCEPTANCE_AUTHORITY_SEED_CHIRHO),
            custody_pin_chirho,
        ),
    }
}

fn member_projection_chirho(
    raft_chirho: u64,
    seed_chirho: u8,
    role_chirho: GeoMemberRoleChirho,
) -> GeoClusterConfigMemberProjectionV1Chirho {
    GeoClusterConfigMemberProjectionV1Chirho {
        raft_id_chirho: GeoRaftIdChirho::new_chirho(raft_chirho).unwrap(),
        node_key_chirho: derived_pk_chirho(seed_chirho),
        role_chirho,
        endpoint_chirho: GeoEndpointAddressV1Chirho {
            address_chirho: GeoIpAddressChirho::Ipv4Chirho([10, seed_chirho, 0, 1]),
            port_chirho: GeoPortChirho::new_chirho(9001).unwrap(),
        },
    }
}

fn config_source_chirho(
    self_raft_chirho: u64,
    self_seed_chirho: u8,
) -> GeoClusterConfigProjectionSourceV1Chirho {
    GeoClusterConfigProjectionSourceV1Chirho {
        schema_chirho: GeoClusterConfigProjectionSchemaChirho::V1Chirho,
        consistency_group_chirho: GeoConsistencyGroupDigestChirho::new_chirho([55; 32]).unwrap(),
        local_raft_id_chirho: GeoRaftIdChirho::new_chirho(self_raft_chirho).unwrap(),
        node_key_chirho: derived_pk_chirho(self_seed_chirho),
        tick_ms_chirho: 50,
        members_chirho: vec![
            member_projection_chirho(1, MEMBER_SEEDS_CHIRHO[0], GeoMemberRoleChirho::VoterChirho),
            member_projection_chirho(2, MEMBER_SEEDS_CHIRHO[1], GeoMemberRoleChirho::VoterChirho),
            member_projection_chirho(
                3,
                MEMBER_SEEDS_CHIRHO[2],
                GeoMemberRoleChirho::LearnerChirho,
            ),
        ],
    }
}

fn config_sources_chirho() -> Vec<GeoClusterConfigProjectionSourceV1Chirho> {
    vec![
        config_source_chirho(1, MEMBER_SEEDS_CHIRHO[0]),
        config_source_chirho(2, MEMBER_SEEDS_CHIRHO[1]),
        config_source_chirho(3, MEMBER_SEEDS_CHIRHO[2]),
    ]
}

/// A full valid setup: a plan whose builds bind the safe-projection digests, the bound custody presence
/// (over a private guard dir), and the config cross-bind. Returns the guard dir for snapshot + cleanup.
fn full_setup_chirho() -> (
    VerifiedGeoGenesisPlanChirho,
    VerifiedGenesisCustodyPresenceChirho,
    VerifiedGenesisConfigCrossBindChirho,
    PathBuf,
) {
    let sources_chirho = config_sources_chirho();
    let digests_chirho = [
        cluster_config_projection_digest_chirho(&sources_chirho[0]).unwrap(),
        cluster_config_projection_digest_chirho(&sources_chirho[1]).unwrap(),
        cluster_config_projection_digest_chirho(&sources_chirho[2]).unwrap(),
    ];
    let (verified_plan_chirho, _ledger_chirho) =
        verified_plan_with_config_projections_chirho(digests_chirho);
    let (guard_root_chirho, guard_dir_chirho) = temp_guard_root_chirho();
    let config_chirho = valid_config_chirho(guard_root_chirho);
    let presence_chirho =
        verify_custody_presence_chirho(&verified_plan_chirho, &config_chirho).unwrap();
    let cross_chirho =
        cross_bind_member_configs_chirho(&verified_plan_chirho, &sources_chirho).unwrap();
    (
        verified_plan_chirho,
        presence_chirho,
        cross_chirho,
        guard_dir_chirho,
    )
}

#[test]
fn dry_run_packet_is_safe_counts_and_round_trips_chirho() {
    let (plan_chirho, presence_chirho, cross_chirho, guard_dir_chirho) = full_setup_chirho();
    let packet_chirho =
        build_dry_run_packet_chirho(&plan_chirho, &presence_chirho, &cross_chirho).unwrap();

    assert_eq!(packet_chirho.member_count_chirho, 3);
    assert_eq!(packet_chirho.voter_count_chirho, 2);
    assert_eq!(packet_chirho.learner_count_chirho, 1);
    assert_eq!(packet_chirho.provider_count_chirho, 3);
    assert_eq!(packet_chirho.region_count_chirho, 3);
    assert_eq!(packet_chirho.config_projection_digests_chirho.len(), 3);
    assert_eq!(
        packet_chirho.plan_digest_chirho,
        plan_chirho.plan_digest_chirho()
    );

    let bytes_chirho = canonical_dry_run_packet_chirho(&packet_chirho).unwrap();
    // The real packet bytes carry ZERO forbidden markers (safety by typing).
    assert!(scan_forbidden_markers_chirho(&bytes_chirho).is_ok());
    let verified_chirho = verify_dry_run_packet_chirho(&bytes_chirho).unwrap();
    assert_eq!(verified_chirho, packet_chirho);

    std::fs::remove_dir_all(&guard_dir_chirho).unwrap();
}

#[test]
fn each_forbidden_marker_class_fires_its_own_reason_chirho() {
    // Every marker in every class, fed directly, is refused by that class's reason (a live-rule proof).
    let cases_chirho: [(&[&str], GeoDryRunLeakReasonChirho); 5] = [
        (
            DRY_RUN_HOST_PATH_MARKERS_CHIRHO,
            GeoDryRunLeakReasonChirho::ForbiddenHostPathChirho,
        ),
        (
            DRY_RUN_BEARER_MARKERS_CHIRHO,
            GeoDryRunLeakReasonChirho::ForbiddenBearerMarkerChirho,
        ),
        (
            DRY_RUN_PRINCIPAL_MARKERS_CHIRHO,
            GeoDryRunLeakReasonChirho::ForbiddenPrincipalMarkerChirho,
        ),
        (
            DRY_RUN_PROVIDER_MARKERS_CHIRHO,
            GeoDryRunLeakReasonChirho::ForbiddenProviderBytesChirho,
        ),
        (
            DRY_RUN_ENDPOINT_MARKERS_CHIRHO,
            GeoDryRunLeakReasonChirho::ForbiddenEndpointChirho,
        ),
    ];
    for (markers_chirho, expected_reason_chirho) in cases_chirho {
        for marker_chirho in markers_chirho {
            assert_eq!(
                scan_forbidden_markers_chirho(marker_chirho.as_bytes()).unwrap_err(),
                GeoGenesisRefusalChirho::DryRunPacketRefusedChirho {
                    reason_chirho: expected_reason_chirho
                },
                "marker {marker_chirho:?} must fire {expected_reason_chirho:?}"
            );
        }
    }

    // Planted composite positive controls (one realistic needle per class).
    let planted_chirho: [(&str, GeoDryRunLeakReasonChirho); 5] = [
        (
            "{\"root\":\"/etc/cairn-chirho/x\"}",
            GeoDryRunLeakReasonChirho::ForbiddenHostPathChirho,
        ),
        (
            "authorization: bearer secret-token",
            GeoDryRunLeakReasonChirho::ForbiddenBearerMarkerChirho,
        ),
        (
            "{\"email_address\":\"owner@example.com\"}",
            GeoDryRunLeakReasonChirho::ForbiddenPrincipalMarkerChirho,
        ),
        (
            "{\"raw_provider_bytes\":\"...\"}",
            GeoDryRunLeakReasonChirho::ForbiddenProviderBytesChirho,
        ),
        (
            "{\"listen_addr\":\"10.0.0.1:9001\"}",
            GeoDryRunLeakReasonChirho::ForbiddenEndpointChirho,
        ),
    ];
    for (needle_chirho, expected_reason_chirho) in planted_chirho {
        assert_eq!(
            scan_forbidden_markers_chirho(needle_chirho.as_bytes()).unwrap_err(),
            GeoGenesisRefusalChirho::DryRunPacketRefusedChirho {
                reason_chirho: expected_reason_chirho
            }
        );
    }
}

#[test]
fn building_the_packet_generates_no_key_and_no_side_effect_chirho() {
    let (plan_chirho, presence_chirho, cross_chirho, guard_dir_chirho) = full_setup_chirho();

    let before_chirho = std::fs::read_dir(&guard_dir_chirho).unwrap().count();
    let packet_chirho =
        build_dry_run_packet_chirho(&plan_chirho, &presence_chirho, &cross_chirho).unwrap();
    let bytes_chirho = canonical_dry_run_packet_chirho(&packet_chirho).unwrap();
    let _verified_chirho = verify_dry_run_packet_chirho(&bytes_chirho).unwrap();
    let after_chirho = std::fs::read_dir(&guard_dir_chirho).unwrap().count();

    // No file, marker, key, or guard subdirectory was created by the dry run.
    assert_eq!(before_chirho, 0);
    assert_eq!(after_chirho, 0);
    assert!(!guard_dir_chirho.join("geo-genesis-guard-chirho").exists());

    std::fs::remove_dir_all(&guard_dir_chirho).unwrap();
}

#[test]
fn tampered_packet_and_mismatched_tokens_refuse_chirho() {
    let (plan_chirho, presence_chirho, cross_chirho, guard_dir_chirho) = full_setup_chirho();
    let packet_chirho =
        build_dry_run_packet_chirho(&plan_chirho, &presence_chirho, &cross_chirho).unwrap();

    // Tampered count breaks the integrity digest.
    let mut tampered_chirho = packet_chirho.clone();
    tampered_chirho.member_count_chirho += 1;
    let tampered_bytes_chirho = serde_json::to_vec(&tampered_chirho).unwrap();
    assert_eq!(
        verify_dry_run_packet_chirho(&tampered_bytes_chirho).unwrap_err(),
        GeoGenesisRefusalChirho::DryRunPacketRefusedChirho {
            reason_chirho: GeoDryRunLeakReasonChirho::IntegrityDigestChirho
        }
    );

    // Tokens bound to a DIFFERENT plan refuse the binding: a custody presence over the base fixture
    // plan cannot summarize the config-projection-bound plan.
    let (base_plan_chirho, _base_ledger_chirho) = verified_valid_plan_chirho();
    let (other_guard_chirho, other_dir_chirho) = temp_guard_root_chirho();
    let base_presence_chirho =
        verify_custody_presence_chirho(&base_plan_chirho, &valid_config_chirho(other_guard_chirho))
            .unwrap();
    assert_eq!(
        build_dry_run_packet_chirho(&plan_chirho, &base_presence_chirho, &cross_chirho)
            .unwrap_err(),
        GeoGenesisRefusalChirho::DryRunTokenBindingRefusedChirho
    );

    std::fs::remove_dir_all(&guard_dir_chirho).unwrap();
    std::fs::remove_dir_all(&other_dir_chirho).unwrap();
}

#[test]
fn config_cross_bind_over_a_different_plan_refuses_binding_chirho() {
    // The token-binding check has a SECOND disjunct: the config cross-bind must bind the SAME plan as
    // the packet. Here the custody presence still matches the packet's plan (so the first,
    // custody-presence disjunct is inert), while the config cross-bind is bound to a DIFFERENT plan —
    // so ONLY the config-cross-bind disjunct can produce the refusal. This is the symmetric arm to the
    // mismatched-presence case in `tampered_packet_and_mismatched_tokens_refuse_chirho`.
    let (plan_chirho, presence_chirho, _cross_chirho, guard_dir_chirho) = full_setup_chirho();

    // A cross-bind proven end-to-end over a SECOND plan with different config projections: a different
    // election cadence gives different projection digests, hence a different plan digest. Building the
    // plan from those digests and cross-binding the same sources yields a genuine, non-fabricated
    // cross-bind token that is simply bound to the other plan.
    let mut other_sources_chirho = config_sources_chirho();
    for source_chirho in &mut other_sources_chirho {
        source_chirho.tick_ms_chirho = 60;
    }
    let other_digests_chirho = [
        cluster_config_projection_digest_chirho(&other_sources_chirho[0]).unwrap(),
        cluster_config_projection_digest_chirho(&other_sources_chirho[1]).unwrap(),
        cluster_config_projection_digest_chirho(&other_sources_chirho[2]).unwrap(),
    ];
    let (other_plan_chirho, _other_ledger_chirho) =
        verified_plan_with_config_projections_chirho(other_digests_chirho);
    let other_cross_chirho =
        cross_bind_member_configs_chirho(&other_plan_chirho, &other_sources_chirho).unwrap();

    // The two plans genuinely differ, so the binding check is exercised rather than a tautology.
    assert_ne!(
        other_cross_chirho.plan_digest_chirho(),
        plan_chirho.plan_digest_chirho()
    );
    // Presence binds the packet's plan; only the config-cross-bind disjunct mismatches.
    assert_eq!(
        build_dry_run_packet_chirho(&plan_chirho, &presence_chirho, &other_cross_chirho)
            .unwrap_err(),
        GeoGenesisRefusalChirho::DryRunTokenBindingRefusedChirho
    );

    std::fs::remove_dir_all(&guard_dir_chirho).unwrap();
}

/// Writes the operator crate's dry-run fixture: one canonical packet built from this file's full setup.
/// Ignored: run it with `--ignored` only after a packet schema change.
#[test]
#[ignore = "regenerates the geo-genesis operator crate's dry-run fixture; run explicitly after a schema change"]
fn export_operator_dry_run_fixture_chirho() {
    let (plan_chirho, presence_chirho, cross_chirho, guard_dir_chirho) = full_setup_chirho();
    let packet_chirho =
        build_dry_run_packet_chirho(&plan_chirho, &presence_chirho, &cross_chirho).unwrap();
    let bytes_chirho = canonical_dry_run_packet_chirho(&packet_chirho).unwrap();
    let dir_chirho = super::fixtures_chirho::operator_fixture_dir_chirho();
    std::fs::create_dir_all(&dir_chirho).unwrap();
    std::fs::write(dir_chirho.join("dry-run-packet-chirho.json"), bytes_chirho).unwrap();
    let _removed_chirho = std::fs::remove_dir_all(guard_dir_chirho);
}
