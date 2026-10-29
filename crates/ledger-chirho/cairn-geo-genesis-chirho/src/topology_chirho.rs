// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Topology and build-evidence types (design sections 5.4-5.5): the exact sorted voter/learner
//! population, each member's public identities/endpoints/custody, and one reviewed build artifact per
//! member. Validation here is structural — sort, uniqueness, spread, target agreement, and coarse-time
//! order; the ruled item-7 N cross-check and custody non-equivalence predicate are 8.2b/8.3.

use crate::digest_chirho::{
    GeoBinarySha256Chirho, GeoCustodyVerifierRefChirho, GeoNodeConfigEvidenceRefChirho,
    GeoNodeConfigProjectionDigestChirho, GeoRosterProjectionDigestChirho,
};
use crate::error_chirho::{
    GeoGenesisRefusalChirho, GeoGenesisResultChirho, GeoMemberCoordinateChirho,
};
use crate::metadata_chirho::{
    GeoBuildTargetChirho, GeoMemberRoleChirho, GeoProviderChirho, GeoRegionChirho,
};
use crate::scalar_chirho::{
    GeoAppliedConfIndexChirho, GeoAppliedRosterRevisionChirho, GeoEd25519PublicKeyChirho,
    GeoGitCommitIdChirho, GeoIpAddressChirho, GeoPortChirho, GeoRaftIdChirho, GeoSmallCountChirho,
    GeoUtcMinuteChirho, GeoWireGuardPublicKeyChirho,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Representable member-population band; the ruled item-7 N imposes the stronger acceptance floor.
pub const GEO_MIN_MEMBERS_CHIRHO: usize = 3;
pub const GEO_MAX_MEMBERS_CHIRHO: usize = 64;
/// Bound on a member's redacted custody verifier-ref set.
pub const GEO_MAX_CUSTODY_VERIFIER_REFS_CHIRHO: usize = 8;

/// One numeric transport endpoint: an address plus a nonzero port. No URL, hostname, path, or query.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoEndpointAddressV1Chirho {
    pub address_chirho: GeoIpAddressChirho,
    pub port_chirho: GeoPortChirho,
}

/// Exactly one endpoint per required role, made one-per-role by type: three named fields, not a set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoEndpointSetV1Chirho {
    pub election_chirho: GeoEndpointAddressV1Chirho,
    pub mirror_chirho: GeoEndpointAddressV1Chirho,
    pub capability_read_chirho: GeoEndpointAddressV1Chirho,
}

impl GeoEndpointSetV1Chirho {
    fn all_chirho(&self) -> [GeoEndpointAddressV1Chirho; 3] {
        [
            self.election_chirho,
            self.mirror_chirho,
            self.capability_read_chirho,
        ]
    }

    fn has_internal_collision_chirho(&self) -> bool {
        let endpoints_chirho = self.all_chirho();
        let unique_chirho: BTreeSet<_> = endpoints_chirho.iter().collect();
        unique_chirho.len() != endpoints_chirho.len()
    }
}

/// A member's custody binding: a public custody key plus redacted verifier refs. No secret name or
/// key bytes; the two-evidence non-equivalence predicate lives in 8.2b/8.3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoNodeCustodyBindingV1Chirho {
    pub custody_key_chirho: GeoEd25519PublicKeyChirho,
    pub verifier_refs_chirho: Vec<GeoCustodyVerifierRefChirho>,
}

impl GeoNodeCustodyBindingV1Chirho {
    fn validate_chirho(&self) -> GeoGenesisResultChirho<()> {
        let refs_chirho = &self.verifier_refs_chirho;
        if refs_chirho.is_empty() || refs_chirho.len() > GEO_MAX_CUSTODY_VERIFIER_REFS_CHIRHO {
            return Err(GeoGenesisRefusalChirho::CustodyBindingRefusedChirho);
        }
        if !refs_chirho
            .windows(2)
            .all(|pair_chirho| pair_chirho[0] < pair_chirho[1])
        {
            return Err(GeoGenesisRefusalChirho::CustodyBindingRefusedChirho);
        }
        Ok(())
    }
}

/// One planned member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoMemberPlanV1Chirho {
    pub role_chirho: GeoMemberRoleChirho,
    pub raft_id_chirho: GeoRaftIdChirho,
    pub node_key_chirho: GeoEd25519PublicKeyChirho,
    pub wireguard_key_chirho: GeoWireGuardPublicKeyChirho,
    pub provider_chirho: GeoProviderChirho,
    pub region_chirho: GeoRegionChirho,
    pub build_target_chirho: GeoBuildTargetChirho,
    pub endpoints_chirho: GeoEndpointSetV1Chirho,
    pub custody_chirho: GeoNodeCustodyBindingV1Chirho,
    pub config_evidence_chirho: GeoNodeConfigEvidenceRefChirho,
}

/// The exact planned topology: signed-roster and applied-configuration coordinates, failure-domain
/// minimums, and the sorted member population.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoTopologyPlanV1Chirho {
    pub roster_projection_chirho: GeoRosterProjectionDigestChirho,
    pub applied_roster_revision_chirho: GeoAppliedRosterRevisionChirho,
    pub required_applied_conf_index_chirho: GeoAppliedConfIndexChirho,
    pub minimum_provider_count_chirho: GeoSmallCountChirho,
    pub minimum_region_count_chirho: GeoSmallCountChirho,
    pub members_chirho: Vec<GeoMemberPlanV1Chirho>,
}

/// One member's reviewed build artifact and config evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoMemberBuildEvidenceV1Chirho {
    pub node_key_chirho: GeoEd25519PublicKeyChirho,
    pub target_chirho: GeoBuildTargetChirho,
    pub binary_sha256_chirho: GeoBinarySha256Chirho,
    pub config_projection_chirho: GeoNodeConfigProjectionDigestChirho,
    pub config_evidence_ref_chirho: GeoNodeConfigEvidenceRefChirho,
    pub measured_at_chirho: GeoUtcMinuteChirho,
    pub freshness_deadline_chirho: GeoUtcMinuteChirho,
}

/// Exactly one build artifact per topology member, in member order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoBuildEvidenceSetV1Chirho {
    pub reviewed_source_commit_chirho: GeoGitCommitIdChirho,
    pub members_chirho: Vec<GeoMemberBuildEvidenceV1Chirho>,
}

/// Structural topology validation: count band, ascending-unique Raft ids, unique keys and endpoints,
/// at least one voter, and the declared provider/region failure-domain spread.
pub(crate) fn validate_topology_chirho(
    topology_chirho: &GeoTopologyPlanV1Chirho,
) -> GeoGenesisResultChirho<()> {
    let members_chirho = &topology_chirho.members_chirho;
    if members_chirho.len() < GEO_MIN_MEMBERS_CHIRHO
        || members_chirho.len() > GEO_MAX_MEMBERS_CHIRHO
    {
        return Err(GeoGenesisRefusalChirho::MemberCountOutOfRangeChirho);
    }
    if !members_chirho
        .windows(2)
        .all(|pair_chirho| pair_chirho[0].raft_id_chirho < pair_chirho[1].raft_id_chirho)
    {
        return Err(GeoGenesisRefusalChirho::MembersNotSortedChirho);
    }

    let mut node_keys_chirho = BTreeSet::new();
    let mut wireguard_keys_chirho = BTreeSet::new();
    let mut endpoints_chirho = BTreeSet::new();
    let mut providers_chirho = BTreeSet::new();
    let mut regions_chirho = BTreeSet::new();
    let mut voter_count_chirho = 0usize;
    for member_chirho in members_chirho {
        member_chirho.custody_chirho.validate_chirho()?;
        if !node_keys_chirho.insert(member_chirho.node_key_chirho) {
            return Err(duplicate_chirho(GeoMemberCoordinateChirho::NodeKeyChirho));
        }
        if !wireguard_keys_chirho.insert(member_chirho.wireguard_key_chirho) {
            return Err(duplicate_chirho(
                GeoMemberCoordinateChirho::WireGuardKeyChirho,
            ));
        }
        if member_chirho
            .endpoints_chirho
            .has_internal_collision_chirho()
        {
            return Err(GeoGenesisRefusalChirho::EndpointRoleRefusedChirho);
        }
        for endpoint_chirho in member_chirho.endpoints_chirho.all_chirho() {
            if !endpoints_chirho.insert(endpoint_chirho) {
                return Err(duplicate_chirho(GeoMemberCoordinateChirho::EndpointChirho));
            }
        }
        if matches!(member_chirho.role_chirho, GeoMemberRoleChirho::VoterChirho) {
            voter_count_chirho += 1;
        }
        providers_chirho.insert(member_chirho.provider_chirho);
        regions_chirho.insert(member_chirho.region_chirho);
    }
    if voter_count_chirho == 0 {
        return Err(GeoGenesisRefusalChirho::MemberRoleCountRefusedChirho);
    }
    if providers_chirho.len() < topology_chirho.minimum_provider_count_chirho.get_chirho() as usize
    {
        return Err(GeoGenesisRefusalChirho::ProviderSpreadRefusedChirho);
    }
    if regions_chirho.len() < topology_chirho.minimum_region_count_chirho.get_chirho() as usize {
        return Err(GeoGenesisRefusalChirho::RegionSpreadRefusedChirho);
    }
    Ok(())
}

/// Structural build-set validation: one build per member in member order, target agreement, and
/// coarse measure-before-deadline order.
pub(crate) fn validate_builds_chirho(
    builds_chirho: &GeoBuildEvidenceSetV1Chirho,
    topology_chirho: &GeoTopologyPlanV1Chirho,
) -> GeoGenesisResultChirho<()> {
    if builds_chirho.members_chirho.len() != topology_chirho.members_chirho.len() {
        return Err(GeoGenesisRefusalChirho::BuildMemberMismatchChirho);
    }
    for (build_chirho, member_chirho) in builds_chirho
        .members_chirho
        .iter()
        .zip(&topology_chirho.members_chirho)
    {
        if build_chirho.node_key_chirho != member_chirho.node_key_chirho {
            return Err(GeoGenesisRefusalChirho::BuildMemberMismatchChirho);
        }
        if build_chirho.target_chirho != member_chirho.build_target_chirho {
            return Err(GeoGenesisRefusalChirho::BuildTargetMismatchChirho);
        }
        if build_chirho.measured_at_chirho.get_chirho()
            > build_chirho.freshness_deadline_chirho.get_chirho()
        {
            return Err(GeoGenesisRefusalChirho::TimeOrderRefusedChirho);
        }
    }
    Ok(())
}

/// The earliest member build freshness deadline; `execute_not_after` may not exceed it.
pub(crate) fn earliest_build_deadline_chirho(
    builds_chirho: &GeoBuildEvidenceSetV1Chirho,
) -> Option<u32> {
    builds_chirho
        .members_chirho
        .iter()
        .map(|build_chirho| build_chirho.freshness_deadline_chirho.get_chirho())
        .min()
}

fn duplicate_chirho(coordinate_chirho: GeoMemberCoordinateChirho) -> GeoGenesisRefusalChirho {
    GeoGenesisRefusalChirho::DuplicateMemberCoordinateChirho { coordinate_chirho }
}
