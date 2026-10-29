// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The acceptance PURE verifier (coordinator ruling 6): verify a signed acceptance packet against the
//! acceptance-authority pin and a verified plan, and check the section-6.3 equations computable from
//! the packet's typed values. Returns a private verified token.
//!
//! Scope at 8.2b (ruling 6 — item-5/6/7 evidence refs are contract-digest STUBS): this checks the
//! packet's own signature (the acceptance-authority boundary), the plan cross-binding, and the
//! structural/count/verdict equations 1, 2, 3, 4, 7, 9, 10. The evidence-CONTENT equations 5 and 6
//! (item-5 terminal/certificate populations, item-6 provider/compensation/receipt counts), equation 8
//! (capability reads under the ruled serving evidence), the distinct-domain half of equation 4, the
//! item-7-receipt-set value match half of equation 3, and the nested publication/member-admission
//! receipt SIGNATURE verification all require the live evidence loaders and bind at 8.7. Their refs are
//! present-and-typed here but not expanded.

use crate::acceptance_chirho::{
    parse_canonical_acceptance_chirho, GeoGenesisAcceptancePacketV1Chirho,
    GeoOneWriterVerdictChirho, GeoSurvivingRegionReadVerdictChirho,
};
use crate::codec_chirho::canonical_record_bytes_chirho;
use crate::error_chirho::{GeoGenesisRefusalChirho, GeoGenesisResultChirho};
use crate::gate_chirho::GeoProductHardGatesClosedV1Chirho;
use crate::metadata_chirho::GeoGgVerdictChirho;
use crate::trust_chirho::{
    verify_class_signature_chirho, GeoGenesisMessageClassChirho, GeoGenesisTrustPinsChirho,
    GeoSignerRoleChirho,
};
use crate::verify_chirho::VerifiedGeoGenesisPlanChirho;
use std::collections::BTreeSet;

/// An acceptance packet that passed the acceptance verify order under a set of custody pins and a
/// verified plan. Private fields, no public constructor — a caller cannot fabricate a verified
/// acceptance; the only way to obtain one is `verify_acceptance_packet_chirho`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGeoGenesisAcceptanceChirho {
    packet_chirho: GeoGenesisAcceptancePacketV1Chirho,
    canonical_bytes_chirho: Vec<u8>,
}

impl VerifiedGeoGenesisAcceptanceChirho {
    /// The verified acceptance packet.
    pub fn packet_chirho(&self) -> &GeoGenesisAcceptancePacketV1Chirho {
        &self.packet_chirho
    }

    /// The exact canonical bytes that were verified.
    pub fn canonical_bytes_chirho(&self) -> &[u8] {
        &self.canonical_bytes_chirho
    }
}

fn equation_refusal_chirho(equation_chirho: u8) -> GeoGenesisRefusalChirho {
    GeoGenesisRefusalChirho::AcceptanceEquationRefusedChirho { equation_chirho }
}

/// Bind the acceptance packet to the verified plan: it must name the exact plan digest, instance,
/// trust profile, and hard gates it claims to accept.
fn bind_acceptance_to_plan_chirho(
    packet_chirho: &GeoGenesisAcceptancePacketV1Chirho,
    verified_plan_chirho: &VerifiedGeoGenesisPlanChirho,
) -> GeoGenesisResultChirho<()> {
    let plan_chirho = verified_plan_chirho.plan_chirho();
    if packet_chirho.plan_ref_chirho != verified_plan_chirho.plan_digest_chirho()
        || packet_chirho.instance_id_chirho != plan_chirho.instance_id_chirho
        || packet_chirho.trust_profile_chirho != plan_chirho.trust_profile_chirho
        || packet_chirho.hard_gates_chirho != plan_chirho.hard_gates_chirho
    {
        return Err(GeoGenesisRefusalChirho::AcceptancePlanBindingRefusedChirho);
    }
    Ok(())
}

/// The section-6.3 equations computable from the packet's typed values and the verified plan.
fn check_acceptance_equations_chirho(
    packet_chirho: &GeoGenesisAcceptancePacketV1Chirho,
    verified_plan_chirho: &VerifiedGeoGenesisPlanChirho,
) -> GeoGenesisResultChirho<()> {
    let plan_chirho = verified_plan_chirho.plan_chirho();
    let observed_chirho = &packet_chirho.observed_topology_chirho;
    let members_chirho = &plan_chirho.topology_chirho.members_chirho;
    let admissions_chirho = &packet_chirho
        .root_publication_chirho
        .member_admissions_chirho;

    // Equation 1: observed voter + learner count equals the exact planned member population.
    let observed_population_chirho = (observed_chirho.voter_count_chirho.get_chirho() as usize)
        .checked_add(observed_chirho.learner_count_chirho.get_chirho() as usize)
        .ok_or_else(|| equation_refusal_chirho(1))?;
    if observed_population_chirho != members_chirho.len() {
        return Err(equation_refusal_chirho(1));
    }

    // Equation 2: one authoritative root publication (exactly one by type), and every planned member
    // appears once in the admission set. (The observed-member projection ref and the publication
    // receipt signature bind at 8.7.)
    if admissions_chirho.len() != members_chirho.len() {
        return Err(equation_refusal_chirho(2));
    }
    let admission_keys_chirho: BTreeSet<_> = admissions_chirho
        .iter()
        .map(|admission_chirho| admission_chirho.node_key_chirho)
        .collect();
    let member_keys_chirho: BTreeSet<_> = members_chirho
        .iter()
        .map(|member_chirho| member_chirho.node_key_chirho)
        .collect();
    if admission_keys_chirho != member_keys_chirho {
        return Err(equation_refusal_chirho(2));
    }

    // Equation 3: every admission's winner term, roster revision, and applied conf index match the
    // observed topology by value, and the observed revision/index meet or exceed the plan requirement.
    // (The item-7 receipt-set value match binds at 8.7.)
    for admission_chirho in admissions_chirho {
        if admission_chirho.winner_term_chirho != observed_chirho.final_election_term_chirho
            || admission_chirho.applied_roster_revision_chirho
                != observed_chirho.applied_roster_revision_chirho
            || admission_chirho.applied_conf_index_chirho
                != observed_chirho.applied_conf_index_chirho
        {
            return Err(equation_refusal_chirho(3));
        }
    }
    if observed_chirho.applied_roster_revision_chirho.get_chirho()
        < plan_chirho
            .topology_chirho
            .applied_roster_revision_chirho
            .get_chirho()
        || observed_chirho.applied_conf_index_chirho.get_chirho()
            < plan_chirho
                .topology_chirho
                .required_applied_conf_index_chirho
                .get_chirho()
    {
        return Err(equation_refusal_chirho(3));
    }

    // Equation 4: finalized mirror receipts satisfy the ruled N (required holder count). The
    // distinct-domain constraint binds at 8.7.
    if observed_chirho
        .finalized_mirror_receipt_count_chirho
        .get_chirho()
        < plan_chirho
            .evidence_contracts_chirho
            .item7_receipt_requirement_chirho
            .required_holder_count_chirho
            .get_chirho()
    {
        return Err(equation_refusal_chirho(4));
    }

    // Equation 7: loss evidence preserves one writer and a served surviving-region read. (The loss
    // drill evidence content — leader/node/region — and stale-sink refusal bind at 8.7.)
    if observed_chirho.one_writer_chirho != GeoOneWriterVerdictChirho::OneWriterPreservedChirho
        || observed_chirho.surviving_region_read_chirho
            != GeoSurvivingRegionReadVerdictChirho::SurvivingReadServedChirho
    {
        return Err(equation_refusal_chirho(7));
    }

    // Equation 9: every hard gate remains closed. Closed by type; this is the concrete equality check.
    if packet_chirho.hard_gates_chirho != GeoProductHardGatesClosedV1Chirho::all_closed_chirho() {
        return Err(equation_refusal_chirho(9));
    }

    // Equation 10: GG1-GG7 verified-satisfied, GG8 standing-additive, phase hosted-accepted. Structural
    // validation already fixes the phase and gg1-5/7 satisfied + gg8 standing; acceptance ADDITIONALLY
    // requires GG6 satisfied (not merely wiring-ready), which the plan did not require.
    if packet_chirho
        .gg_dispositions_chirho
        .gg6_chirho
        .verdict_chirho
        != GeoGgVerdictChirho::VerifiedSatisfiedChirho
    {
        return Err(equation_refusal_chirho(10));
    }

    Ok(())
}

/// Verify a signed acceptance packet against the custody pins and a verified plan. Parse (deny
/// unknown/dup, canonical, structural), bind to the plan, require the acceptance-authority pin and
/// verify the packet signature over the Acceptance class, check the computable section-6.3 equations,
/// and require byte-identical canonical bytes. Item-5/6/7 evidence content and nested receipt
/// signatures bind at 8.7. No caller-provided signer override exists.
pub fn verify_acceptance_packet_chirho(
    candidate_bytes_chirho: &[u8],
    pins_chirho: &GeoGenesisTrustPinsChirho,
    verified_plan_chirho: &VerifiedGeoGenesisPlanChirho,
) -> GeoGenesisResultChirho<VerifiedGeoGenesisAcceptanceChirho> {
    // Parse + structural (fixed HostedAccepted phase, publication-set structure, GG verdicts, monotone
    // times).
    let packet_chirho = parse_canonical_acceptance_chirho(candidate_bytes_chirho)?;

    // Bind to the verified plan.
    bind_acceptance_to_plan_chirho(&packet_chirho, verified_plan_chirho)?;

    // The custody-pinned acceptance-authority key verifies; the embedded key must equal it.
    let expected_key_chirho = pins_chirho
        .expected_authority_key_chirho(GeoSignerRoleChirho::AcceptanceAuthorityChirho)
        .ok_or(GeoGenesisRefusalChirho::TrustPinsRefusedChirho)?;
    if packet_chirho.acceptance_signer_key_chirho != expected_key_chirho {
        return Err(GeoGenesisRefusalChirho::CustodyPinMismatchChirho);
    }
    let unsigned_bytes_chirho = canonical_record_bytes_chirho(&packet_chirho.to_unsigned_chirho())?;
    verify_class_signature_chirho(
        &expected_key_chirho,
        GeoGenesisMessageClassChirho::AcceptanceChirho,
        &unsigned_bytes_chirho,
        &packet_chirho.signature_chirho,
    )?;

    // The computable section-6.3 equations.
    check_acceptance_equations_chirho(&packet_chirho, verified_plan_chirho)?;

    // Byte-identical canonical re-encode.
    let canonical_bytes_chirho = canonical_record_bytes_chirho(&packet_chirho)?;
    if canonical_bytes_chirho != candidate_bytes_chirho {
        return Err(GeoGenesisRefusalChirho::NotCanonicalChirho);
    }

    Ok(VerifiedGeoGenesisAcceptanceChirho {
        packet_chirho,
        canonical_bytes_chirho,
    })
}
