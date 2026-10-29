// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Operator-only geo-genesis vocabulary + wire law (8.2a) and the signer boundary (8.2b): the typed
//! plan/acceptance/marker records and their canonical codec, plus the dual-key trust split, the
//! plan author, the custody-pinned plan verifier, the custody non-equivalence predicate, and the
//! acceptance pure verifier, plus the durable one-time fork-impossible genesis intent guard
//! (`intent_guard_chirho`, 8.2c). It signs with EXISTING keys only and calls no key generator (no generation call site, no RNG in scope; never-generate is enforced by the 8.2c source-census guard, not by compile-time gating, since ed25519-dalek rand_core is feature-unified workspace-wide); the
//! source-census guard lives in cairn-source-scan-chirho, and the serve runtime has no edge here.

#![forbid(unsafe_code)]

mod acceptance_chirho;
mod acceptance_verify_chirho;
mod author_chirho;
mod codec_chirho;
mod config_projection_chirho;
mod custody_chirho;
mod custody_presence_chirho;
mod digest_chirho;
mod dry_run_packet_chirho;
mod error_chirho;
mod gate_chirho;
mod intent_chirho;
mod intent_guard_chirho;
mod metadata_chirho;
mod plan_chirho;
mod ruling_chirho;
mod scalar_chirho;
mod topology_chirho;
mod trust_chirho;
mod verify_chirho;

pub use acceptance_chirho::*;
pub use acceptance_verify_chirho::{
    verify_acceptance_packet_chirho, VerifiedGeoGenesisAcceptanceChirho,
};
pub use author_chirho::author_plan_chirho;
pub use codec_chirho::canonical_blake3_hex_chirho;
pub use config_projection_chirho::{
    cluster_config_projection_digest_chirho, cross_bind_member_configs_chirho,
    load_cluster_config_projection_source_chirho, parse_cluster_config_projection_source_chirho,
    verify_cluster_config_projection_custody_chirho, GeoClusterConfigMemberProjectionV1Chirho,
    GeoClusterConfigProjectionSchemaChirho, GeoClusterConfigProjectionSourceV1Chirho,
    VerifiedGenesisConfigCrossBindChirho, MAX_CLUSTER_CONFIG_PROJECTION_BYTES_CHIRHO,
};
pub use custody_chirho::{
    verify_custody_non_equivalence_chirho, GeoCustodyAttestationSchemaChirho,
    GeoCustodyAttestationV1Chirho, GeoCustodyDomainIdChirho, UnsignedGeoCustodyAttestationV1Chirho,
    VerifiedCustodyNonEquivalenceChirho,
};
pub use custody_presence_chirho::{
    verify_custody_presence_chirho, GeoMemberCustodyPinV1Chirho, GeoOperatorCustodyConfigV1Chirho,
    VerifiedGenesisCustodyPresenceChirho,
};
pub use digest_chirho::*;
pub use dry_run_packet_chirho::{
    build_dry_run_packet_chirho, canonical_dry_run_packet_chirho, verify_dry_run_packet_chirho,
    GeoGenesisDryRunPacketV1Chirho, GeoGenesisDryRunSchemaChirho,
};
pub use error_chirho::{
    GeoDryRunLeakReasonChirho, GeoGenesisRefusalChirho, GeoGenesisResultChirho,
    GeoGuardHolderRoleChirho, GeoMemberCoordinateChirho, GeoRulingFieldChirho,
};
pub use gate_chirho::{
    GeoProductHardGatesClosedV1Chirho, ProductionMoneyGateChirho,
    ProductionRealUserEmailGateChirho, PublicSignupGateChirho, PublicWebhookGateChirho,
};
pub use intent_chirho::*;
pub use intent_guard_chirho::{
    build_signed_intent_marker_chirho, geo_genesis_guard_marker_path_chirho,
    reserve_genesis_intent_chirho, reserve_intent_then_run_root_chirho,
    GeoGenesisIntentReservationChirho, GeoGuardRootsChirho, GeoMemberGuardRootChirho,
    GeoOperatorGuardRootChirho, SignedIntentMarkerChirho, AUTHORITATIVE_INTENT_FILE_CHIRHO,
    GEO_GENESIS_GUARD_DIR_CHIRHO,
};
pub use metadata_chirho::{
    GeoBuildTargetChirho, GeoCanaryKindChirho, GeoEndpointRoleChirho, GeoGenesisPhaseChirho,
    GeoGgKeyChirho, GeoGgVerdictChirho, GeoMemberAdmissionPhaseChirho, GeoMemberRoleChirho,
    GeoProviderChirho, GeoRegionChirho,
};
pub use plan_chirho::*;
pub use ruling_chirho::{
    GeoCellAdvanceRulingChirho, GeoGenesisRulingSetV1Chirho, GeoGenesisTrustProfileChirho,
    GeoGg6OrderingRulingChirho, GeoItem7ClosureChirho, GeoItem7DurabilityChirho,
    GeoItem7FailureSemanticsChirho, GeoItem7MembershipFreshnessChirho, GeoItem7ReadServingChirho,
    GeoItem7ReplicaCountChirho, GeoItem7RulingSetV1Chirho,
};
pub use scalar_chirho::{
    GeoAppliedConfIndexChirho, GeoAppliedRosterRevisionChirho, GeoEd25519PublicKeyChirho,
    GeoEd25519SignatureChirho, GeoElectionTermChirho, GeoFreshRootIdentityChirho,
    GeoGenesisInstanceIdChirho, GeoGitCommitIdChirho, GeoIpAddressChirho, GeoPortChirho,
    GeoRaftIdChirho, GeoSmallCountChirho, GeoTenantRootIdentityChirho, GeoUtcMinuteChirho,
    GeoWireGuardPublicKeyChirho, GEO_UTC_MINUTE_MAX_CHIRHO,
};
pub use topology_chirho::*;
pub use trust_chirho::{
    GeoGenesisMessageClassChirho, GeoGenesisTrustPinsChirho, GeoRoleSignerChirho,
    GeoSignerRoleChirho,
};
pub use verify_chirho::{verify_plan_chirho, VerifiedGeoGenesisPlanChirho};

#[cfg(test)]
#[path = "tests_chirho/mod_tests_chirho.rs"]
mod tests_chirho;
