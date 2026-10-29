// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Acceptance pure-verifier arms (8.2b, ruling 6): an acceptance packet signed by the custody-pinned
//! acceptance authority and consistent with a verified plan verifies byte-identical; the plan binding,
//! the acceptance-authority pin/signature, and the computable section-6.3 equations (1, 2, 3, 4, 7,
//! 10) each fail-closed on a targeted, honestly re-signed mutation. Equation 9 is closed by type;
//! equations 5, 6, 8 and nested-receipt signatures bind at 8.7.

use super::fixtures_chirho::*;
use crate::acceptance_chirho::*;
use crate::acceptance_verify_chirho::verify_acceptance_packet_chirho;
use crate::codec_chirho::canonical_record_bytes_chirho;
use crate::digest_chirho::*;
use crate::error_chirho::GeoGenesisRefusalChirho;
use crate::gate_chirho::GeoProductHardGatesClosedV1Chirho;
use crate::intent_chirho::*;
use crate::metadata_chirho::*;
use crate::plan_chirho::{GeoGgDispositionSetV1Chirho, GeoGgDispositionV1Chirho};
use crate::ruling_chirho::GeoGenesisTrustProfileChirho;
use crate::scalar_chirho::*;
use crate::trust_chirho::{
    GeoGenesisMessageClassChirho, GeoGenesisTrustPinsChirho, GeoRoleSignerChirho,
    GeoSignerRoleChirho,
};

const ACCEPTANCE_TERM_CHIRHO: u64 = 2;
const ACCEPTANCE_ROSTER_REVISION_CHIRHO: u64 = 4;
const ACCEPTANCE_CONF_INDEX_CHIRHO: u64 = 1;

fn plan_ref_digest_chirho() -> GeoGenesisPlanDigestChirho {
    GeoGenesisPlanDigestChirho::new_chirho([200; 32]).unwrap()
}
fn intent_ref_chirho() -> GeoGenesisIntentDigestChirho {
    GeoGenesisIntentDigestChirho::new_chirho([3; 32]).unwrap()
}
fn placeholder_sig_chirho() -> GeoEd25519SignatureChirho {
    GeoEd25519SignatureChirho::new_chirho([9; 64]).unwrap()
}
fn instance_chirho() -> GeoGenesisInstanceIdChirho {
    GeoGenesisInstanceIdChirho::new_chirho([PLAN_INSTANCE_SEED_CHIRHO; 32]).unwrap()
}

fn satisfied_gg_chirho(seed_chirho: u8) -> GeoGgDispositionV1Chirho {
    GeoGgDispositionV1Chirho {
        verdict_chirho: GeoGgVerdictChirho::VerifiedSatisfiedChirho,
        evidence_ref_chirho: GeoGgEvidenceRefChirho::new_chirho([seed_chirho; 32]).unwrap(),
    }
}

/// Nested receipt signatures are NOT verified at 8.2b (they bind at 8.7), so these carry placeholders.
fn admission_chirho(raft_chirho: u64, seed_chirho: u8) -> GeoGenesisMemberAdmissionReceiptV1Chirho {
    GeoGenesisMemberAdmissionReceiptV1Chirho {
        schema_chirho: GeoGenesisMemberAdmissionReceiptSchemaChirho::V1Chirho,
        instance_id_chirho: instance_chirho(),
        plan_ref_chirho: plan_ref_digest_chirho(),
        marker_ref_chirho: intent_ref_chirho(),
        fresh_root_identity_chirho: GeoFreshRootIdentityChirho::new_chirho([22; 32]).unwrap(),
        consistency_group_chirho: GeoConsistencyGroupDigestChirho::new_chirho([23; 32]).unwrap(),
        tenant_root_chirho: GeoTenantRootIdentityChirho::new_chirho([24; 32]).unwrap(),
        role_chirho: GeoMemberRoleChirho::VoterChirho,
        raft_id_chirho: GeoRaftIdChirho::new_chirho(raft_chirho).unwrap(),
        node_key_chirho: derived_pk_chirho(seed_chirho),
        winner_term_chirho: GeoElectionTermChirho::new_chirho(ACCEPTANCE_TERM_CHIRHO).unwrap(),
        applied_roster_revision_chirho: GeoAppliedRosterRevisionChirho::new_chirho(
            ACCEPTANCE_ROSTER_REVISION_CHIRHO,
        )
        .unwrap(),
        applied_conf_index_chirho: GeoAppliedConfIndexChirho::new_chirho(
            ACCEPTANCE_CONF_INDEX_CHIRHO,
        )
        .unwrap(),
        build_evidence_ref_chirho: GeoNodeBuildEvidenceRefChirho::new_chirho([seed_chirho; 32])
            .unwrap(),
        config_evidence_ref_chirho: GeoNodeConfigEvidenceRefChirho::new_chirho([seed_chirho; 32])
            .unwrap(),
        admitted_at_chirho: GeoUtcMinuteChirho::new_chirho(1800).unwrap(),
        phase_chirho: GeoMemberAdmissionPhaseChirho::AdmittedChirho,
        receipt_signer_key_chirho: derived_pk_chirho(seed_chirho),
        signature_chirho: placeholder_sig_chirho(),
    }
}

fn publication_receipt_chirho() -> GeoGenesisPublicationReceiptV1Chirho {
    GeoGenesisPublicationReceiptV1Chirho {
        schema_chirho: GeoGenesisPublicationReceiptSchemaChirho::V1Chirho,
        instance_id_chirho: instance_chirho(),
        plan_ref_chirho: plan_ref_digest_chirho(),
        marker_ref_chirho: intent_ref_chirho(),
        ledger_plan_chirho: GeoLedgerRegenesisPlanDigestChirho::new_chirho([21; 32]).unwrap(),
        fresh_root_identity_chirho: GeoFreshRootIdentityChirho::new_chirho([22; 32]).unwrap(),
        ledger_publication_manifest_chirho: GeoLedgerPublicationManifestDigestChirho::new_chirho(
            [26; 32],
        )
        .unwrap(),
        published_epoch_chirho: 7,
        published_at_chirho: GeoUtcMinuteChirho::new_chirho(1600).unwrap(),
        phase_chirho: GeoGenesisPhaseChirho::RootPublishedChirho,
        receipt_signer_key_chirho: derived_pk_chirho(ACCEPTANCE_AUTHORITY_SEED_CHIRHO),
        signature_chirho: placeholder_sig_chirho(),
    }
}

fn evidence_set_chirho() -> GeoAcceptanceEvidenceSetV1Chirho {
    GeoAcceptanceEvidenceSetV1Chirho {
        item5_terminal_chirho: GeoItem5TerminalEvidenceRefChirho::new_chirho([101; 32]).unwrap(),
        item5_certificate_chirho: GeoItem5CertificateEvidenceRefChirho::new_chirho([102; 32])
            .unwrap(),
        item6_manifest_chirho: GeoItem6ManifestRefChirho::new_chirho([103; 32]).unwrap(),
        item7_contract_chirho: GeoItem7ContractRefChirho::new_chirho([104; 32]).unwrap(),
        item7_receipts_chirho: GeoItem7ReceiptSetRefChirho::new_chirho([105; 32]).unwrap(),
        item7_read_serving_chirho: GeoItem7ReadServingEvidenceRefChirho::new_chirho([106; 32])
            .unwrap(),
        canary_chirho: GeoCanaryEvidenceRefChirho::new_chirho([107; 32]).unwrap(),
        leader_loss_chirho: GeoLossDrillEvidenceRefChirho::new_chirho([108; 32]).unwrap(),
        node_loss_chirho: GeoLossDrillEvidenceRefChirho::new_chirho([109; 32]).unwrap(),
        whole_region_loss_chirho: GeoLossDrillEvidenceRefChirho::new_chirho([110; 32]).unwrap(),
        heal_failback_chirho: GeoHealFailbackEvidenceRefChirho::new_chirho([111; 32]).unwrap(),
        cf7_packet_chirho: GeoCf7PacketEvidenceRefChirho::new_chirho([112; 32]).unwrap(),
    }
}

fn observed_topology_chirho() -> GeoObservedTopologyV1Chirho {
    let count_chirho = |value_chirho: u16| GeoSmallCountChirho::new_chirho(value_chirho).unwrap();
    GeoObservedTopologyV1Chirho {
        voter_count_chirho: count_chirho(2),
        learner_count_chirho: count_chirho(1),
        provider_count_chirho: count_chirho(3),
        region_count_chirho: count_chirho(3),
        final_election_term_chirho: GeoElectionTermChirho::new_chirho(ACCEPTANCE_TERM_CHIRHO)
            .unwrap(),
        applied_roster_revision_chirho: GeoAppliedRosterRevisionChirho::new_chirho(
            ACCEPTANCE_ROSTER_REVISION_CHIRHO,
        )
        .unwrap(),
        applied_conf_index_chirho: GeoAppliedConfIndexChirho::new_chirho(
            ACCEPTANCE_CONF_INDEX_CHIRHO,
        )
        .unwrap(),
        member_set_chirho: GeoObservedMemberSetRefChirho::new_chirho([61; 32]).unwrap(),
        finalized_mirror_receipt_count_chirho: count_chirho(2),
        surviving_region_read_chirho:
            GeoSurvivingRegionReadVerdictChirho::SurvivingReadServedChirho,
        one_writer_chirho: GeoOneWriterVerdictChirho::OneWriterPreservedChirho,
    }
}

/// A base acceptance packet consistent with the shared plan fixture; `plan_ref` binds the verified
/// plan digest. Signature is a placeholder until signed.
fn base_packet_chirho(
    plan_digest_chirho: GeoGenesisPlanDigestChirho,
) -> GeoGenesisAcceptancePacketV1Chirho {
    GeoGenesisAcceptancePacketV1Chirho {
        schema_chirho: GeoGenesisAcceptanceSchemaChirho::V1Chirho,
        instance_id_chirho: instance_chirho(),
        plan_ref_chirho: plan_digest_chirho,
        intent_marker_set_chirho: GeoIntentMarkerSetRefChirho::new_chirho([55; 32]).unwrap(),
        root_publication_chirho: GeoRootPublicationSetV1Chirho {
            authoritative_root_chirho: publication_receipt_chirho(),
            member_admissions_chirho: vec![
                admission_chirho(1, MEMBER_SEEDS_CHIRHO[0]),
                admission_chirho(2, MEMBER_SEEDS_CHIRHO[1]),
                admission_chirho(3, MEMBER_SEEDS_CHIRHO[2]),
            ],
        },
        gg_dispositions_chirho: GeoGgDispositionSetV1Chirho {
            gg1_chirho: satisfied_gg_chirho(11),
            gg2_chirho: satisfied_gg_chirho(12),
            gg3_chirho: satisfied_gg_chirho(13),
            gg4_chirho: satisfied_gg_chirho(14),
            gg5_chirho: satisfied_gg_chirho(15),
            gg6_chirho: satisfied_gg_chirho(16), // acceptance requires GG6 SATISFIED (eq 10)
            gg7_chirho: satisfied_gg_chirho(17),
            gg8_chirho: GeoGgDispositionV1Chirho {
                verdict_chirho: GeoGgVerdictChirho::StandingAdditiveChirho,
                evidence_ref_chirho: GeoGgEvidenceRefChirho::new_chirho([18; 32]).unwrap(),
            },
        },
        evidence_chirho: evidence_set_chirho(),
        observed_topology_chirho: observed_topology_chirho(),
        phase_chirho: GeoGenesisPhaseChirho::HostedAcceptedChirho,
        hard_gates_chirho: GeoProductHardGatesClosedV1Chirho::all_closed_chirho(),
        started_at_chirho: GeoUtcMinuteChirho::new_chirho(1000).unwrap(),
        accepted_at_chirho: GeoUtcMinuteChirho::new_chirho(2000).unwrap(),
        trust_profile_chirho:
            GeoGenesisTrustProfileChirho::SplitDedicatedPlanAndAcceptanceAuthoritiesChirho,
        acceptance_signer_key_chirho: derived_pk_chirho(ACCEPTANCE_AUTHORITY_SEED_CHIRHO),
        signature_chirho: placeholder_sig_chirho(),
    }
}

fn acceptance_signer_chirho() -> GeoRoleSignerChirho {
    provision_signer_chirho(
        GeoSignerRoleChirho::AcceptanceAuthorityChirho,
        ACCEPTANCE_AUTHORITY_SEED_CHIRHO,
    )
}

/// Sign a packet with the acceptance authority over the Acceptance class and return canonical bytes.
fn sign_packet_bytes_chirho(mut packet_chirho: GeoGenesisAcceptancePacketV1Chirho) -> Vec<u8> {
    let signer_chirho = acceptance_signer_chirho();
    let unsigned_bytes_chirho =
        canonical_record_bytes_chirho(&packet_chirho.to_unsigned_chirho()).unwrap();
    packet_chirho.signature_chirho = signer_chirho
        .sign_class_chirho(
            GeoGenesisMessageClassChirho::AcceptanceChirho,
            &unsigned_bytes_chirho,
        )
        .unwrap();
    canonical_record_bytes_chirho(&packet_chirho).unwrap()
}

/// Build a valid signed packet consistent with the shared verified plan, then verify it.
#[test]
fn pinned_acceptance_verifies_byte_identical_chirho() {
    let (verified_plan_chirho, _ledger_chirho) = verified_valid_plan_chirho();
    let bytes_chirho = sign_packet_bytes_chirho(base_packet_chirho(
        verified_plan_chirho.plan_digest_chirho(),
    ));
    let verified_chirho =
        verify_acceptance_packet_chirho(&bytes_chirho, &split_pins_chirho(), &verified_plan_chirho)
            .unwrap();
    assert_eq!(
        verified_chirho.canonical_bytes_chirho(),
        bytes_chirho.as_slice()
    );
    assert_eq!(
        verified_chirho.packet_chirho().phase_chirho,
        GeoGenesisPhaseChirho::HostedAcceptedChirho
    );
    // Byte-identical re-verify.
    assert!(verify_acceptance_packet_chirho(
        verified_chirho.canonical_bytes_chirho(),
        &split_pins_chirho(),
        &verified_plan_chirho
    )
    .is_ok());
}

/// Mutate the packet, re-sign honestly with the acceptance authority, and return the verify refusal.
/// Because the packet is honestly re-signed, only the mutated semantic check can fail.
fn resign_and_expect_refusal_chirho(
    mutate_chirho: impl FnOnce(&mut GeoGenesisAcceptancePacketV1Chirho),
) -> GeoGenesisRefusalChirho {
    let (verified_plan_chirho, _ledger_chirho) = verified_valid_plan_chirho();
    let mut packet_chirho = base_packet_chirho(verified_plan_chirho.plan_digest_chirho());
    mutate_chirho(&mut packet_chirho);
    let bytes_chirho = sign_packet_bytes_chirho(packet_chirho);
    verify_acceptance_packet_chirho(&bytes_chirho, &split_pins_chirho(), &verified_plan_chirho)
        .expect_err("a mutated acceptance packet must not verify")
}

fn equation_chirho(number_chirho: u8) -> GeoGenesisRefusalChirho {
    GeoGenesisRefusalChirho::AcceptanceEquationRefusedChirho {
        equation_chirho: number_chirho,
    }
}

#[test]
fn plan_binding_mismatch_refuses_chirho() {
    // A packet naming a different instance than the plan refuses (re-signed so only the binding fails).
    let actual_chirho = resign_and_expect_refusal_chirho(|packet_chirho| {
        packet_chirho.instance_id_chirho = GeoGenesisInstanceIdChirho::new_chirho([9; 32]).unwrap();
    });
    assert_eq!(
        actual_chirho,
        GeoGenesisRefusalChirho::AcceptancePlanBindingRefusedChirho
    );
}

#[test]
fn wrong_acceptance_pin_and_tampered_signature_refuse_chirho() {
    let (verified_plan_chirho, _ledger_chirho) = verified_valid_plan_chirho();
    let good_bytes_chirho = sign_packet_bytes_chirho(base_packet_chirho(
        verified_plan_chirho.plan_digest_chirho(),
    ));

    // Verify against pins whose acceptance authority is a DIFFERENT key: the packet's embedded key is
    // the real acceptance authority, so the pin does not match.
    let rogue_pins_chirho = GeoGenesisTrustPinsChirho::new_split_chirho(
        derived_pk_chirho(PLAN_AUTHORITY_SEED_CHIRHO),
        derived_pk_chirho(230),
    )
    .unwrap();
    assert_eq!(
        verify_acceptance_packet_chirho(
            &good_bytes_chirho,
            &rogue_pins_chirho,
            &verified_plan_chirho
        ),
        Err(GeoGenesisRefusalChirho::CustodyPinMismatchChirho)
    );

    // Flip a signature byte: pin matches but the signature no longer verifies.
    let mut tampered_chirho = base_packet_chirho(verified_plan_chirho.plan_digest_chirho());
    let bytes_chirho = sign_packet_bytes_chirho(tampered_chirho.clone());
    let parsed_chirho = parse_canonical_acceptance_chirho(&bytes_chirho).unwrap();
    tampered_chirho = parsed_chirho;
    let mut sig_bytes_chirho = *tampered_chirho.signature_chirho.as_bytes_chirho();
    sig_bytes_chirho[3] ^= 0x01;
    tampered_chirho.signature_chirho =
        GeoEd25519SignatureChirho::new_chirho(sig_bytes_chirho).unwrap();
    let tampered_bytes_chirho = canonical_record_bytes_chirho(&tampered_chirho).unwrap();
    assert_eq!(
        verify_acceptance_packet_chirho(
            &tampered_bytes_chirho,
            &split_pins_chirho(),
            &verified_plan_chirho
        ),
        Err(GeoGenesisRefusalChirho::SignatureRefusedChirho)
    );
}

#[test]
fn each_computable_equation_fails_closed_chirho() {
    // Eq 1: observed population != planned.
    let actual_chirho = resign_and_expect_refusal_chirho(|packet_chirho| {
        packet_chirho.observed_topology_chirho.voter_count_chirho =
            GeoSmallCountChirho::new_chirho(5).unwrap();
    });
    assert_eq!(actual_chirho, equation_chirho(1));

    // Eq 2: an admission names a member that is not in the plan population.
    let actual_chirho = resign_and_expect_refusal_chirho(|packet_chirho| {
        packet_chirho
            .root_publication_chirho
            .member_admissions_chirho[1]
            .node_key_chirho = derived_pk_chirho(99);
    });
    assert_eq!(actual_chirho, equation_chirho(2));

    // Eq 3: an admission's winner term disagrees with the observed topology.
    let actual_chirho = resign_and_expect_refusal_chirho(|packet_chirho| {
        packet_chirho
            .root_publication_chirho
            .member_admissions_chirho[0]
            .winner_term_chirho = GeoElectionTermChirho::new_chirho(3).unwrap();
    });
    assert_eq!(actual_chirho, equation_chirho(3));

    // Eq 4: finalized mirror receipts below the ruled required holder count.
    let actual_chirho = resign_and_expect_refusal_chirho(|packet_chirho| {
        packet_chirho
            .observed_topology_chirho
            .finalized_mirror_receipt_count_chirho = GeoSmallCountChirho::new_chirho(1).unwrap();
    });
    assert_eq!(actual_chirho, equation_chirho(4));

    // Eq 7: multiple writers observed.
    let actual_chirho = resign_and_expect_refusal_chirho(|packet_chirho| {
        packet_chirho.observed_topology_chirho.one_writer_chirho =
            GeoOneWriterVerdictChirho::MultipleWritersObservedChirho;
    });
    assert_eq!(actual_chirho, equation_chirho(7));

    // Eq 10: GG6 is only wiring-ready, not satisfied (acceptance requires satisfied).
    let actual_chirho = resign_and_expect_refusal_chirho(|packet_chirho| {
        packet_chirho
            .gg_dispositions_chirho
            .gg6_chirho
            .verdict_chirho = GeoGgVerdictChirho::VerifiedWiringReadyChirho;
    });
    assert_eq!(actual_chirho, equation_chirho(10));
}
