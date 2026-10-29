// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Config cross-bind arms (8.3): each member's SAFE cluster-config projection digests to the exact
//! `config_projection_chirho` the verified plan binds; a mismatched config, an uncovered population, a
//! custody-failing file, and a structurally invalid source each refuse by their own reason. The cross-
//! bind starts no elector and creates no root — it digests in-memory safe projections only.

use super::fixtures_chirho::{
    derived_pk_chirho, verified_plan_with_config_projections_chirho, MEMBER_SEEDS_CHIRHO,
};
use crate::error_chirho::GeoGenesisRefusalChirho;
use crate::{
    cluster_config_projection_digest_chirho, cross_bind_member_configs_chirho,
    load_cluster_config_projection_source_chirho, parse_cluster_config_projection_source_chirho,
    GeoClusterConfigMemberProjectionV1Chirho, GeoClusterConfigProjectionSchemaChirho,
    GeoClusterConfigProjectionSourceV1Chirho, GeoConsistencyGroupDigestChirho,
    GeoEndpointAddressV1Chirho, GeoIpAddressChirho, GeoMemberRoleChirho,
    GeoNodeConfigProjectionDigestChirho, GeoPortChirho, GeoRaftIdChirho,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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

/// The cluster view every node's config shares: raft 1/2/3, sorted, matching the fixture plan seeds.
fn cluster_members_view_chirho() -> Vec<GeoClusterConfigMemberProjectionV1Chirho> {
    vec![
        member_projection_chirho(1, MEMBER_SEEDS_CHIRHO[0], GeoMemberRoleChirho::VoterChirho),
        member_projection_chirho(2, MEMBER_SEEDS_CHIRHO[1], GeoMemberRoleChirho::VoterChirho),
        member_projection_chirho(
            3,
            MEMBER_SEEDS_CHIRHO[2],
            GeoMemberRoleChirho::LearnerChirho,
        ),
    ]
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
        members_chirho: cluster_members_view_chirho(),
    }
}

/// The three member config sources plus a plan whose build config projections are their exact digests.
fn sources_and_bound_plan_chirho() -> (
    Vec<GeoClusterConfigProjectionSourceV1Chirho>,
    crate::VerifiedGeoGenesisPlanChirho,
) {
    let sources_chirho = vec![
        config_source_chirho(1, MEMBER_SEEDS_CHIRHO[0]),
        config_source_chirho(2, MEMBER_SEEDS_CHIRHO[1]),
        config_source_chirho(3, MEMBER_SEEDS_CHIRHO[2]),
    ];
    let digests_chirho: [GeoNodeConfigProjectionDigestChirho; 3] = [
        cluster_config_projection_digest_chirho(&sources_chirho[0]).unwrap(),
        cluster_config_projection_digest_chirho(&sources_chirho[1]).unwrap(),
        cluster_config_projection_digest_chirho(&sources_chirho[2]).unwrap(),
    ];
    let (verified_plan_chirho, _ledger_chirho) =
        verified_plan_with_config_projections_chirho(digests_chirho);
    (sources_chirho, verified_plan_chirho)
}

#[test]
fn configs_parse_and_cross_bind_to_the_plan_projection_digests_chirho() {
    let (sources_chirho, verified_plan_chirho) = sources_and_bound_plan_chirho();
    let cross_chirho =
        cross_bind_member_configs_chirho(&verified_plan_chirho, &sources_chirho).unwrap();
    assert_eq!(cross_chirho.member_count_chirho(), 3);
    assert_eq!(cross_chirho.projection_digests_chirho().len(), 3);
    // The cross-bound digests are exactly the ones the safe projections produce.
    assert!(cross_chirho
        .projection_digests_chirho()
        .contains(&cluster_config_projection_digest_chirho(&sources_chirho[0]).unwrap()));
}

#[test]
fn a_mismatched_config_refuses_by_digest_mismatch_chirho() {
    let (mut sources_chirho, verified_plan_chirho) = sources_and_bound_plan_chirho();
    // Alter one config after the plan bound its digest: a different tick cadence -> different digest.
    sources_chirho[1].tick_ms_chirho = 60;
    assert_eq!(
        cross_bind_member_configs_chirho(&verified_plan_chirho, &sources_chirho).unwrap_err(),
        GeoGenesisRefusalChirho::ConfigProjectionDigestMismatchChirho
    );
}

#[test]
fn an_uncovered_population_refuses_by_coverage_chirho() {
    // Fewer sources than plan members.
    let (mut sources_chirho, verified_plan_chirho) = sources_and_bound_plan_chirho();
    sources_chirho.pop();
    assert_eq!(
        cross_bind_member_configs_chirho(&verified_plan_chirho, &sources_chirho).unwrap_err(),
        GeoGenesisRefusalChirho::ConfigCrossBindCoverageRefusedChirho
    );

    // Right count, but one source names a member not in the plan (no build matches its node key).
    let (mut foreign_sources_chirho, foreign_plan_chirho) = sources_and_bound_plan_chirho();
    foreign_sources_chirho[2].node_key_chirho = derived_pk_chirho(200);
    assert_eq!(
        cross_bind_member_configs_chirho(&foreign_plan_chirho, &foreign_sources_chirho)
            .unwrap_err(),
        GeoGenesisRefusalChirho::ConfigCrossBindCoverageRefusedChirho
    );
}

#[test]
fn a_structurally_invalid_source_refuses_before_a_digest_exists_chirho() {
    // Unsorted members: no single canonical order.
    let mut unsorted_chirho = config_source_chirho(1, MEMBER_SEEDS_CHIRHO[0]);
    unsorted_chirho.members_chirho.swap(0, 1);
    let bytes_chirho = serde_json::to_vec(&unsorted_chirho).unwrap();
    assert_eq!(
        parse_cluster_config_projection_source_chirho(&bytes_chirho).unwrap_err(),
        GeoGenesisRefusalChirho::ConfigProjectionSourceRefusedChirho
    );

    // Local node absent from the member view.
    let mut foreign_local_chirho = config_source_chirho(9, 90);
    foreign_local_chirho.local_raft_id_chirho = GeoRaftIdChirho::new_chirho(9).unwrap();
    let foreign_bytes_chirho = serde_json::to_vec(&foreign_local_chirho).unwrap();
    assert_eq!(
        parse_cluster_config_projection_source_chirho(&foreign_bytes_chirho).unwrap_err(),
        GeoGenesisRefusalChirho::ConfigProjectionSourceRefusedChirho
    );
}

#[test]
fn canonical_round_trip_holds_chirho() {
    let source_chirho = config_source_chirho(1, MEMBER_SEEDS_CHIRHO[0]);
    let bytes_chirho = serde_json::to_vec(&source_chirho).unwrap();
    let parsed_chirho = parse_cluster_config_projection_source_chirho(&bytes_chirho).unwrap();
    assert_eq!(parsed_chirho, source_chirho);
    // Deterministic digest.
    assert_eq!(
        cluster_config_projection_digest_chirho(&source_chirho).unwrap(),
        cluster_config_projection_digest_chirho(&parsed_chirho).unwrap()
    );
}

fn unique_temp_path_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let ordinal_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-geo-83-config-{nanos_chirho}-{ordinal_chirho}.json"
    ))
}

#[cfg(unix)]
#[test]
fn config_file_custody_accepts_private_and_refuses_broad_and_symlink_chirho() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let source_chirho = config_source_chirho(1, MEMBER_SEEDS_CHIRHO[0]);
    let bytes_chirho = serde_json::to_vec(&source_chirho).unwrap();
    let path_chirho = unique_temp_path_chirho();
    std::fs::write(&path_chirho, &bytes_chirho).unwrap();
    std::fs::set_permissions(&path_chirho, std::fs::Permissions::from_mode(0o600)).unwrap();
    // Private, regular file: loads and parses to the same source.
    assert_eq!(
        load_cluster_config_projection_source_chirho(&path_chirho).unwrap(),
        source_chirho
    );

    // Broad mode refuses.
    std::fs::set_permissions(&path_chirho, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        load_cluster_config_projection_source_chirho(&path_chirho).unwrap_err(),
        GeoGenesisRefusalChirho::ConfigProjectionSourceCustodyRefusedChirho
    );

    // Symlink refuses.
    std::fs::set_permissions(&path_chirho, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link_chirho = unique_temp_path_chirho();
    symlink(&path_chirho, &link_chirho).unwrap();
    assert_eq!(
        load_cluster_config_projection_source_chirho(&link_chirho).unwrap_err(),
        GeoGenesisRefusalChirho::ConfigProjectionSourceCustodyRefusedChirho
    );

    std::fs::remove_file(&link_chirho).unwrap();
    std::fs::remove_file(&path_chirho).unwrap();
}
