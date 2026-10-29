// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The shareable `GeoGenesisAcceptancePacketV1Chirho` (design section 6), its explicit unsigned
//! companion, the actual-evidence set, and the observed-topology counts/verdicts. This is the wire
//! law + structural shape (phase-by-type, monotone times, publication-set structure); the ten
//! acceptance equations of section 6.3 and the signed evidence verification are the 8.2b pure verifier.

use crate::codec_chirho::parse_canonical_chirho;
use crate::digest_chirho::{
    GeoCanaryEvidenceRefChirho, GeoCf7PacketEvidenceRefChirho, GeoGenesisPlanDigestChirho,
    GeoHealFailbackEvidenceRefChirho, GeoIntentMarkerSetRefChirho,
    GeoItem5CertificateEvidenceRefChirho, GeoItem5TerminalEvidenceRefChirho,
    GeoItem6ManifestRefChirho, GeoItem7ContractRefChirho, GeoItem7ReadServingEvidenceRefChirho,
    GeoItem7ReceiptSetRefChirho, GeoLossDrillEvidenceRefChirho, GeoObservedMemberSetRefChirho,
};
use crate::error_chirho::{GeoGenesisRefusalChirho, GeoGenesisResultChirho};
use crate::gate_chirho::GeoProductHardGatesClosedV1Chirho;
use crate::intent_chirho::GeoRootPublicationSetV1Chirho;
use crate::metadata_chirho::GeoGenesisPhaseChirho;
use crate::plan_chirho::GeoGgDispositionSetV1Chirho;
use crate::ruling_chirho::GeoGenesisTrustProfileChirho;
use crate::scalar_chirho::{
    GeoAppliedConfIndexChirho, GeoAppliedRosterRevisionChirho, GeoEd25519PublicKeyChirho,
    GeoEd25519SignatureChirho, GeoElectionTermChirho, GeoGenesisInstanceIdChirho,
    GeoSmallCountChirho, GeoUtcMinuteChirho,
};
use serde::{Deserialize, Serialize};

/// Closed acceptance schema token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoGenesisAcceptanceSchemaChirho {
    V1Chirho,
}

/// Closed surviving-region read verdict; the acceptance equation (8.2b) requires the served value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoSurvivingRegionReadVerdictChirho {
    SurvivingReadServedChirho,
    SurvivingReadUnavailableChirho,
}

/// Closed one-writer verdict; the acceptance equation (8.2b) requires the preserved value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoOneWriterVerdictChirho {
    OneWriterPreservedChirho,
    MultipleWritersObservedChirho,
}

/// The actual verified-evidence set bound after genesis (design section 6.2). Each ref is a
/// class-specific safe projection, never raw rows or bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoAcceptanceEvidenceSetV1Chirho {
    pub item5_terminal_chirho: GeoItem5TerminalEvidenceRefChirho,
    pub item5_certificate_chirho: GeoItem5CertificateEvidenceRefChirho,
    pub item6_manifest_chirho: GeoItem6ManifestRefChirho,
    pub item7_contract_chirho: GeoItem7ContractRefChirho,
    pub item7_receipts_chirho: GeoItem7ReceiptSetRefChirho,
    pub item7_read_serving_chirho: GeoItem7ReadServingEvidenceRefChirho,
    pub canary_chirho: GeoCanaryEvidenceRefChirho,
    pub leader_loss_chirho: GeoLossDrillEvidenceRefChirho,
    pub node_loss_chirho: GeoLossDrillEvidenceRefChirho,
    pub whole_region_loss_chirho: GeoLossDrillEvidenceRefChirho,
    pub heal_failback_chirho: GeoHealFailbackEvidenceRefChirho,
    pub cf7_packet_chirho: GeoCf7PacketEvidenceRefChirho,
}

/// Observed final topology (design section 6.3): counts, freshness coordinates, a safe member-set
/// ref, finalized mirror-receipt count, and the two closed acceptance verdicts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoObservedTopologyV1Chirho {
    pub voter_count_chirho: GeoSmallCountChirho,
    pub learner_count_chirho: GeoSmallCountChirho,
    pub provider_count_chirho: GeoSmallCountChirho,
    pub region_count_chirho: GeoSmallCountChirho,
    pub final_election_term_chirho: GeoElectionTermChirho,
    pub applied_roster_revision_chirho: GeoAppliedRosterRevisionChirho,
    pub applied_conf_index_chirho: GeoAppliedConfIndexChirho,
    pub member_set_chirho: GeoObservedMemberSetRefChirho,
    pub finalized_mirror_receipt_count_chirho: GeoSmallCountChirho,
    pub surviving_region_read_chirho: GeoSurvivingRegionReadVerdictChirho,
    pub one_writer_chirho: GeoOneWriterVerdictChirho,
}

/// The separately signed, redaction-safe acceptance result (design section 6.1). It carries no
/// numeric endpoints; the topology is bound through safe projection refs and counts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoGenesisAcceptancePacketV1Chirho {
    pub schema_chirho: GeoGenesisAcceptanceSchemaChirho,
    pub instance_id_chirho: GeoGenesisInstanceIdChirho,
    pub plan_ref_chirho: GeoGenesisPlanDigestChirho,
    pub intent_marker_set_chirho: GeoIntentMarkerSetRefChirho,
    pub root_publication_chirho: GeoRootPublicationSetV1Chirho,
    pub gg_dispositions_chirho: GeoGgDispositionSetV1Chirho,
    pub evidence_chirho: GeoAcceptanceEvidenceSetV1Chirho,
    pub observed_topology_chirho: GeoObservedTopologyV1Chirho,
    pub phase_chirho: GeoGenesisPhaseChirho,
    pub hard_gates_chirho: GeoProductHardGatesClosedV1Chirho,
    pub started_at_chirho: GeoUtcMinuteChirho,
    pub accepted_at_chirho: GeoUtcMinuteChirho,
    pub trust_profile_chirho: GeoGenesisTrustProfileChirho,
    pub acceptance_signer_key_chirho: GeoEd25519PublicKeyChirho,
    pub signature_chirho: GeoEd25519SignatureChirho,
}

/// The explicit unsigned companion of the acceptance packet (design section 10) — the sixth and last
/// canonical unsigned companion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedGeoGenesisAcceptancePacketV1Chirho {
    pub schema_chirho: GeoGenesisAcceptanceSchemaChirho,
    pub instance_id_chirho: GeoGenesisInstanceIdChirho,
    pub plan_ref_chirho: GeoGenesisPlanDigestChirho,
    pub intent_marker_set_chirho: GeoIntentMarkerSetRefChirho,
    pub root_publication_chirho: GeoRootPublicationSetV1Chirho,
    pub gg_dispositions_chirho: GeoGgDispositionSetV1Chirho,
    pub evidence_chirho: GeoAcceptanceEvidenceSetV1Chirho,
    pub observed_topology_chirho: GeoObservedTopologyV1Chirho,
    pub phase_chirho: GeoGenesisPhaseChirho,
    pub hard_gates_chirho: GeoProductHardGatesClosedV1Chirho,
    pub started_at_chirho: GeoUtcMinuteChirho,
    pub accepted_at_chirho: GeoUtcMinuteChirho,
    pub trust_profile_chirho: GeoGenesisTrustProfileChirho,
    pub acceptance_signer_key_chirho: GeoEd25519PublicKeyChirho,
}

impl GeoGenesisAcceptancePacketV1Chirho {
    /// The explicit unsigned view whose canonical bytes are the signing/verification input (8.2b).
    pub fn to_unsigned_chirho(&self) -> UnsignedGeoGenesisAcceptancePacketV1Chirho {
        UnsignedGeoGenesisAcceptancePacketV1Chirho {
            schema_chirho: self.schema_chirho,
            instance_id_chirho: self.instance_id_chirho,
            plan_ref_chirho: self.plan_ref_chirho,
            intent_marker_set_chirho: self.intent_marker_set_chirho,
            root_publication_chirho: self.root_publication_chirho.clone(),
            gg_dispositions_chirho: self.gg_dispositions_chirho,
            evidence_chirho: self.evidence_chirho,
            observed_topology_chirho: self.observed_topology_chirho,
            phase_chirho: self.phase_chirho,
            hard_gates_chirho: self.hard_gates_chirho,
            started_at_chirho: self.started_at_chirho,
            accepted_at_chirho: self.accepted_at_chirho,
            trust_profile_chirho: self.trust_profile_chirho,
            acceptance_signer_key_chirho: self.acceptance_signer_key_chirho,
        }
    }

    /// Structural validation: the fixed `HostedAcceptedChirho` phase, a structurally valid publication
    /// set, structurally valid GG verdicts, and monotone start-before-accept times. The ten acceptance
    /// equations of section 6.3 and the signed-evidence verification are the 8.2b pure verifier.
    pub fn validate_structural_chirho(&self) -> GeoGenesisResultChirho<()> {
        if self.phase_chirho != GeoGenesisPhaseChirho::HostedAcceptedChirho {
            return Err(GeoGenesisRefusalChirho::PhaseRefusedChirho);
        }
        self.root_publication_chirho.validate_structural_chirho()?;
        self.gg_dispositions_chirho.validate_chirho()?;
        if self.started_at_chirho.get_chirho() > self.accepted_at_chirho.get_chirho() {
            return Err(GeoGenesisRefusalChirho::TimeOrderRefusedChirho);
        }
        Ok(())
    }
}

/// Parse a candidate acceptance packet for review: wire law plus structural validation. The section
/// 6.3 acceptance equations are the 8.2b pure verifier and are not enforced here.
pub fn parse_canonical_acceptance_chirho(
    bytes_chirho: &[u8],
) -> GeoGenesisResultChirho<GeoGenesisAcceptancePacketV1Chirho> {
    let packet_chirho: GeoGenesisAcceptancePacketV1Chirho = parse_canonical_chirho(bytes_chirho)?;
    packet_chirho.validate_structural_chirho()?;
    Ok(packet_chirho)
}
