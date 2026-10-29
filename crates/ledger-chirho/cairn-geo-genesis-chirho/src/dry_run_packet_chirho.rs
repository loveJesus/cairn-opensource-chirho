// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The redaction-safe genesis DRY-RUN packet (design section 11 exclusion table): a shareable summary
//! of a verified plan plus its bound custody presence and config cross-bind, carrying ONLY counts,
//! closed enums, and projection digests — never a numeric endpoint, raw config byte, secret/key ref, or
//! host path — with a defense-in-depth forbidden-marker no-leak scan over the encoded bytes.

use crate::codec_chirho::canonical_blake3_hex_chirho;
use crate::config_projection_chirho::VerifiedGenesisConfigCrossBindChirho;
use crate::custody_chirho::GeoCustodyDomainIdChirho;
use crate::custody_presence_chirho::VerifiedGenesisCustodyPresenceChirho;
use crate::digest_chirho::{
    GeoGenesisPlanDigestChirho, GeoLedgerRegenesisPlanDigestChirho,
    GeoNodeConfigProjectionDigestChirho, GeoOperatorGuardIdentityChirho,
    GeoRosterProjectionDigestChirho,
};
use crate::error_chirho::{
    GeoDryRunLeakReasonChirho, GeoGenesisRefusalChirho, GeoGenesisResultChirho,
};
use crate::gate_chirho::GeoProductHardGatesClosedV1Chirho;
use crate::metadata_chirho::GeoMemberRoleChirho;
use crate::ruling_chirho::GeoGenesisTrustProfileChirho;
use crate::verify_chirho::VerifiedGeoGenesisPlanChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Domain-separated integrity-digest tag for the dry-run packet.
const DRY_RUN_PACKET_DIGEST_DOMAIN_CHIRHO: &str = "cairn-geo-genesis/dry-run-packet-v1-chirho";

// The defense-in-depth forbidden-marker sets (each lowercase; the scan lowercases the packet bytes
// once). Safety BY TYPING is the primary control — the packet has no free-text/endpoint/path/key field
// — so this scan is unfirable-by-construction while the packet stays typed; it exists to catch a future
// field that would carry one of these classes, and each set fires its own leak reason.
pub(crate) const DRY_RUN_HOST_PATH_MARKERS_CHIRHO: &[&str] = &[
    "/users/",
    "/private/tmp/",
    "/var/lib/",
    "/etc/",
    "/usr/local/bin/",
    "/tmp/",
    "/home/",
    "/root/",
    "/usr/",
    "/opt/",
    "/srv/",
];
pub(crate) const DRY_RUN_BEARER_MARKERS_CHIRHO: &[&str] =
    &["bearer ", "authorization:", "access_token", "refresh_token"];
pub(crate) const DRY_RUN_PRINCIPAL_MARKERS_CHIRHO: &[&str] = &[
    "principal_name",
    "email_address",
    "free_text_principal",
    "account_id",
    "customer_id",
];
pub(crate) const DRY_RUN_PROVIDER_MARKERS_CHIRHO: &[&str] = &[
    "raw_provider_bytes",
    "provider_payload",
    "stripe_secret",
    "sk_test",
    "sk_live",
];
pub(crate) const DRY_RUN_ENDPOINT_MARKERS_CHIRHO: &[&str] = &[
    "ipv4_chirho",
    "ipv6_chirho",
    "address_chirho",
    "listen_addr",
    "endpoint_chirho",
    "url_chirho",
    "port_chirho",
    "http",
    "://",
];

/// Closed dry-run packet schema token; unknown versions refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoGenesisDryRunSchemaChirho {
    V1Chirho,
}

/// The redaction-safe dry-run packet.
///
/// INVARIANT (design section 11): every field here is typed or bounded — a closed enum, a validated
/// hex digest/identity, or a small count — so the packet has NO free-text, endpoint, path, or key
/// surface. That typing is the PRIMARY privacy control (safety by typing, not scanning). Any new datum
/// that would be a numeric endpoint, raw config byte, secret/key ref, or host path is EXCLUDED by the
/// design and MUST NOT enter this packet. The producer's forbidden-marker scan in
/// `canonical_dry_run_packet_chirho` is defense-in-depth only, unfirable-by-construction while this
/// invariant holds — never rely on it in place of keeping every field typed/bounded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoGenesisDryRunPacketV1Chirho {
    pub schema_chirho: GeoGenesisDryRunSchemaChirho,
    pub plan_digest_chirho: GeoGenesisPlanDigestChirho,
    pub roster_projection_chirho: GeoRosterProjectionDigestChirho,
    pub ledger_regenesis_plan_chirho: GeoLedgerRegenesisPlanDigestChirho,
    pub member_count_chirho: u16,
    pub voter_count_chirho: u16,
    pub learner_count_chirho: u16,
    pub provider_count_chirho: u16,
    pub region_count_chirho: u16,
    pub config_projection_digests_chirho: Vec<GeoNodeConfigProjectionDigestChirho>,
    pub operator_guard_identity_chirho: GeoOperatorGuardIdentityChirho,
    pub plan_custody_domain_chirho: GeoCustodyDomainIdChirho,
    pub acceptance_custody_domain_chirho: GeoCustodyDomainIdChirho,
    pub trust_profile_chirho: GeoGenesisTrustProfileChirho,
    pub hard_gates_chirho: GeoProductHardGatesClosedV1Chirho,
    pub packet_digest_chirho: String,
}

/// Build the dry-run packet from the verified plan and its bound custody-presence + config-cross-bind
/// tokens. All three MUST bind the same verified plan; counts are derived with checked arithmetic; the
/// safe config-projection digests come from the cross-bind. NO endpoint, key, path, or config byte is
/// copied in — only counts, closed enums, and digests. This creates and starts nothing.
pub fn build_dry_run_packet_chirho(
    verified_plan_chirho: &VerifiedGeoGenesisPlanChirho,
    custody_presence_chirho: &VerifiedGenesisCustodyPresenceChirho,
    config_cross_bind_chirho: &VerifiedGenesisConfigCrossBindChirho,
) -> GeoGenesisResultChirho<GeoGenesisDryRunPacketV1Chirho> {
    let plan_digest_chirho = verified_plan_chirho.plan_digest_chirho();
    if custody_presence_chirho.plan_digest_chirho() != plan_digest_chirho
        || config_cross_bind_chirho.plan_digest_chirho() != plan_digest_chirho
    {
        return Err(GeoGenesisRefusalChirho::DryRunTokenBindingRefusedChirho);
    }

    let plan_chirho = verified_plan_chirho.plan_chirho();
    let members_chirho = &plan_chirho.topology_chirho.members_chirho;
    let mut voter_chirho = 0usize;
    let mut learner_chirho = 0usize;
    let mut providers_chirho = BTreeSet::new();
    let mut regions_chirho = BTreeSet::new();
    for member_chirho in members_chirho {
        match member_chirho.role_chirho {
            GeoMemberRoleChirho::VoterChirho => voter_chirho += 1,
            GeoMemberRoleChirho::LearnerChirho => learner_chirho += 1,
        }
        providers_chirho.insert(member_chirho.provider_chirho);
        regions_chirho.insert(member_chirho.region_chirho);
    }

    let mut packet_chirho = GeoGenesisDryRunPacketV1Chirho {
        schema_chirho: GeoGenesisDryRunSchemaChirho::V1Chirho,
        plan_digest_chirho,
        roster_projection_chirho: custody_presence_chirho.roster_projection_chirho(),
        ledger_regenesis_plan_chirho: plan_chirho.ledger_chirho.ledger_regenesis_plan_chirho,
        member_count_chirho: count_u16_chirho(members_chirho.len())?,
        voter_count_chirho: count_u16_chirho(voter_chirho)?,
        learner_count_chirho: count_u16_chirho(learner_chirho)?,
        provider_count_chirho: count_u16_chirho(providers_chirho.len())?,
        region_count_chirho: count_u16_chirho(regions_chirho.len())?,
        config_projection_digests_chirho: config_cross_bind_chirho
            .projection_digests_chirho()
            .to_vec(),
        operator_guard_identity_chirho: custody_presence_chirho.operator_guard_identity_chirho(),
        plan_custody_domain_chirho: custody_presence_chirho
            .non_equivalence_chirho()
            .plan_domain_chirho(),
        acceptance_custody_domain_chirho: custody_presence_chirho
            .non_equivalence_chirho()
            .acceptance_domain_chirho(),
        trust_profile_chirho: plan_chirho.trust_profile_chirho,
        hard_gates_chirho: plan_chirho.hard_gates_chirho,
        packet_digest_chirho: String::new(),
    };
    packet_chirho.packet_digest_chirho = packet_integrity_digest_chirho(&packet_chirho);
    Ok(packet_chirho)
}

/// Canonical bytes of a validated dry-run packet, with the defense-in-depth no-leak scan applied. The
/// scan finding zero markers on a typed packet is expected — safety by typing is the primary control.
pub fn canonical_dry_run_packet_chirho(
    packet_chirho: &GeoGenesisDryRunPacketV1Chirho,
) -> GeoGenesisResultChirho<Vec<u8>> {
    validate_dry_run_packet_chirho(packet_chirho)?;
    let bytes_chirho = serde_json::to_vec(packet_chirho)
        .map_err(|_error_chirho| refuse_chirho(GeoDryRunLeakReasonChirho::SchemaChirho))?;
    scan_forbidden_markers_chirho(&bytes_chirho)?;
    Ok(bytes_chirho)
}

/// Parse and verify a dry-run packet: canonical round-trip, integrity digest, and the no-leak scan.
pub fn verify_dry_run_packet_chirho(
    bytes_chirho: &[u8],
) -> GeoGenesisResultChirho<GeoGenesisDryRunPacketV1Chirho> {
    let packet_chirho: GeoGenesisDryRunPacketV1Chirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_error_chirho| refuse_chirho(GeoDryRunLeakReasonChirho::SchemaChirho))?;
    let canonical_chirho = canonical_dry_run_packet_chirho(&packet_chirho)?;
    if canonical_chirho != bytes_chirho {
        return Err(refuse_chirho(GeoDryRunLeakReasonChirho::NonCanonicalChirho));
    }
    scan_forbidden_markers_chirho(bytes_chirho)?;
    Ok(packet_chirho)
}

fn validate_dry_run_packet_chirho(
    packet_chirho: &GeoGenesisDryRunPacketV1Chirho,
) -> GeoGenesisResultChirho<()> {
    if packet_chirho.schema_chirho != GeoGenesisDryRunSchemaChirho::V1Chirho {
        return Err(refuse_chirho(GeoDryRunLeakReasonChirho::SchemaChirho));
    }
    if !is_digest_hex_chirho(&packet_chirho.packet_digest_chirho) {
        return Err(refuse_chirho(GeoDryRunLeakReasonChirho::EmptyDigestChirho));
    }
    if packet_chirho.packet_digest_chirho != packet_integrity_digest_chirho(packet_chirho) {
        return Err(refuse_chirho(
            GeoDryRunLeakReasonChirho::IntegrityDigestChirho,
        ));
    }
    Ok(())
}

fn is_digest_hex_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit())
}

fn packet_integrity_digest_chirho(packet_chirho: &GeoGenesisDryRunPacketV1Chirho) -> String {
    let mut copy_chirho = packet_chirho.clone();
    copy_chirho.packet_digest_chirho.clear();
    let bytes_chirho = serde_json::to_vec(&copy_chirho).expect("dry-run packet is serializable");
    let mut input_chirho =
        Vec::with_capacity(DRY_RUN_PACKET_DIGEST_DOMAIN_CHIRHO.len() + 1 + bytes_chirho.len());
    input_chirho.extend_from_slice(DRY_RUN_PACKET_DIGEST_DOMAIN_CHIRHO.as_bytes());
    input_chirho.push(0u8);
    input_chirho.extend_from_slice(&bytes_chirho);
    canonical_blake3_hex_chirho(&input_chirho)
}

/// The defense-in-depth no-leak scan: refuse if the encoded packet bytes contain any host-path,
/// bearer, free-text-principal, provider-payload, or numeric-endpoint marker. Each class fires its own
/// leak reason so a planted positive control proves the rule is live.
pub(crate) fn scan_forbidden_markers_chirho(bytes_chirho: &[u8]) -> GeoGenesisResultChirho<()> {
    let text_chirho = String::from_utf8_lossy(bytes_chirho).to_ascii_lowercase();
    let contains_any_chirho = |markers_chirho: &[&str]| {
        markers_chirho
            .iter()
            .any(|marker_chirho| text_chirho.contains(marker_chirho))
    };
    if contains_any_chirho(DRY_RUN_HOST_PATH_MARKERS_CHIRHO) {
        return Err(refuse_chirho(
            GeoDryRunLeakReasonChirho::ForbiddenHostPathChirho,
        ));
    }
    if contains_any_chirho(DRY_RUN_BEARER_MARKERS_CHIRHO) {
        return Err(refuse_chirho(
            GeoDryRunLeakReasonChirho::ForbiddenBearerMarkerChirho,
        ));
    }
    if contains_any_chirho(DRY_RUN_PRINCIPAL_MARKERS_CHIRHO) {
        return Err(refuse_chirho(
            GeoDryRunLeakReasonChirho::ForbiddenPrincipalMarkerChirho,
        ));
    }
    if contains_any_chirho(DRY_RUN_PROVIDER_MARKERS_CHIRHO) {
        return Err(refuse_chirho(
            GeoDryRunLeakReasonChirho::ForbiddenProviderBytesChirho,
        ));
    }
    if contains_any_chirho(DRY_RUN_ENDPOINT_MARKERS_CHIRHO) {
        return Err(refuse_chirho(
            GeoDryRunLeakReasonChirho::ForbiddenEndpointChirho,
        ));
    }
    Ok(())
}

fn count_u16_chirho(value_chirho: usize) -> GeoGenesisResultChirho<u16> {
    u16::try_from(value_chirho)
        .map_err(|_error_chirho| GeoGenesisRefusalChirho::DryRunCountOverflowChirho)
}

fn refuse_chirho(reason_chirho: GeoDryRunLeakReasonChirho) -> GeoGenesisRefusalChirho {
    GeoGenesisRefusalChirho::DryRunPacketRefusedChirho { reason_chirho }
}
