// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Record arms for the acceptance packet and the intent/marker/receipt family: canonical round-trip,
//! each Unsigned* companion = its signed record minus the signature, deny-unknown/duplicate, the
//! fixed-phase refusal, the marker holder-kind refusal, and the bounded/sorted/unique set checks.

use crate::acceptance_chirho::*;
use crate::codec_chirho::canonical_record_bytes_chirho;
use crate::digest_chirho::*;
use crate::error_chirho::{GeoGenesisRefusalChirho, GeoMemberCoordinateChirho};
use crate::gate_chirho::GeoProductHardGatesClosedV1Chirho;
use crate::intent_chirho::*;
use crate::metadata_chirho::*;
use crate::plan_chirho::{GeoGgDispositionSetV1Chirho, GeoGgDispositionV1Chirho};
use crate::ruling_chirho::*;
use crate::scalar_chirho::*;

// --- shared builders -------------------------------------------------------------------------

fn pk_chirho(seed_chirho: u8) -> GeoEd25519PublicKeyChirho {
    GeoEd25519PublicKeyChirho::new_chirho([seed_chirho; 32]).unwrap()
}
fn sig_chirho() -> GeoEd25519SignatureChirho {
    GeoEd25519SignatureChirho::new_chirho([9; 64]).unwrap()
}
fn utc_chirho(minute_chirho: u32) -> GeoUtcMinuteChirho {
    GeoUtcMinuteChirho::new_chirho(minute_chirho).unwrap()
}
fn instance_chirho() -> GeoGenesisInstanceIdChirho {
    GeoGenesisInstanceIdChirho::new_chirho([1; 32]).unwrap()
}
fn plan_ref_chirho() -> GeoGenesisPlanDigestChirho {
    GeoGenesisPlanDigestChirho::new_chirho([2; 32]).unwrap()
}
fn intent_ref_chirho() -> GeoGenesisIntentDigestChirho {
    GeoGenesisIntentDigestChirho::new_chirho([3; 32]).unwrap()
}
fn raft_chirho(value_chirho: u64) -> GeoRaftIdChirho {
    GeoRaftIdChirho::new_chirho(value_chirho).unwrap()
}
fn count_chirho(value_chirho: u16) -> GeoSmallCountChirho {
    GeoSmallCountChirho::new_chirho(value_chirho).unwrap()
}

fn resolved_rulings_chirho() -> GeoGenesisRulingSetV1Chirho {
    GeoGenesisRulingSetV1Chirho {
        cell_advance_chirho: GeoCellAdvanceRulingChirho::WinnerForkWitnessOnDemandChirho,
        item7_chirho: GeoItem7RulingSetV1Chirho {
            replica_count_chirho: GeoItem7ReplicaCountChirho::N2ZoneChirho,
            membership_freshness_chirho: GeoItem7MembershipFreshnessChirho::JoinedExactViewChirho,
            durability_chirho: GeoItem7DurabilityChirho::NativeDurabilityChirho,
            closure_chirho: GeoItem7ClosureChirho::ManifestedPrefixClosureChirho,
            failure_semantics_chirho: GeoItem7FailureSemanticsChirho::PrepareCommitFinalizeChirho,
            read_serving_chirho: GeoItem7ReadServingChirho::ReceiptGatedServingChirho,
        },
        gg6_ordering_chirho: GeoGg6OrderingRulingChirho::WiringReadyThenHostedAcceptedChirho,
    }
}

fn member_holder_chirho(raft_value_chirho: u64, node_seed_chirho: u8) -> GeoMarkerHolderV1Chirho {
    GeoMarkerHolderV1Chirho::MemberChirho {
        role_chirho: GeoMemberRoleChirho::VoterChirho,
        raft_id_chirho: raft_chirho(raft_value_chirho),
        node_key_chirho: pk_chirho(node_seed_chirho),
    }
}

fn operator_holder_chirho() -> GeoMarkerHolderV1Chirho {
    GeoMarkerHolderV1Chirho::OperatorGuardChirho {
        guard_identity_chirho: GeoOperatorGuardIdentityChirho::new_chirho([77; 32]).unwrap(),
    }
}

fn marker_receipt_chirho(
    holder_chirho: GeoMarkerHolderV1Chirho,
) -> GeoGenesisMarkerReceiptV1Chirho {
    GeoGenesisMarkerReceiptV1Chirho {
        schema_chirho: GeoGenesisMarkerReceiptSchemaChirho::V1Chirho,
        instance_id_chirho: instance_chirho(),
        plan_ref_chirho: plan_ref_chirho(),
        marker_ref_chirho: intent_ref_chirho(),
        holder_chirho,
        durable_at_chirho: utc_chirho(1500),
        receipt_signer_key_chirho: pk_chirho(70),
        signature_chirho: sig_chirho(),
    }
}

fn admission_chirho(
    raft_value_chirho: u64,
    node_seed_chirho: u8,
) -> GeoGenesisMemberAdmissionReceiptV1Chirho {
    GeoGenesisMemberAdmissionReceiptV1Chirho {
        schema_chirho: GeoGenesisMemberAdmissionReceiptSchemaChirho::V1Chirho,
        instance_id_chirho: instance_chirho(),
        plan_ref_chirho: plan_ref_chirho(),
        marker_ref_chirho: intent_ref_chirho(),
        fresh_root_identity_chirho: GeoFreshRootIdentityChirho::new_chirho([22; 32]).unwrap(),
        consistency_group_chirho: GeoConsistencyGroupDigestChirho::new_chirho([23; 32]).unwrap(),
        tenant_root_chirho: GeoTenantRootIdentityChirho::new_chirho([24; 32]).unwrap(),
        role_chirho: GeoMemberRoleChirho::VoterChirho,
        raft_id_chirho: raft_chirho(raft_value_chirho),
        node_key_chirho: pk_chirho(node_seed_chirho),
        winner_term_chirho: GeoElectionTermChirho::new_chirho(2).unwrap(),
        applied_roster_revision_chirho: GeoAppliedRosterRevisionChirho::new_chirho(4).unwrap(),
        applied_conf_index_chirho: GeoAppliedConfIndexChirho::new_chirho(0).unwrap(),
        build_evidence_ref_chirho: GeoNodeBuildEvidenceRefChirho::new_chirho(
            [node_seed_chirho; 32],
        )
        .unwrap(),
        config_evidence_ref_chirho: GeoNodeConfigEvidenceRefChirho::new_chirho(
            [node_seed_chirho; 32],
        )
        .unwrap(),
        admitted_at_chirho: utc_chirho(1800),
        phase_chirho: GeoMemberAdmissionPhaseChirho::AdmittedChirho,
        receipt_signer_key_chirho: pk_chirho(node_seed_chirho),
        signature_chirho: sig_chirho(),
    }
}

fn publication_receipt_chirho(
    phase_chirho: GeoGenesisPhaseChirho,
) -> GeoGenesisPublicationReceiptV1Chirho {
    GeoGenesisPublicationReceiptV1Chirho {
        schema_chirho: GeoGenesisPublicationReceiptSchemaChirho::V1Chirho,
        instance_id_chirho: instance_chirho(),
        plan_ref_chirho: plan_ref_chirho(),
        marker_ref_chirho: intent_ref_chirho(),
        ledger_plan_chirho: GeoLedgerRegenesisPlanDigestChirho::new_chirho([21; 32]).unwrap(),
        fresh_root_identity_chirho: GeoFreshRootIdentityChirho::new_chirho([22; 32]).unwrap(),
        ledger_publication_manifest_chirho: GeoLedgerPublicationManifestDigestChirho::new_chirho(
            [26; 32],
        )
        .unwrap(),
        published_epoch_chirho: 7,
        published_at_chirho: utc_chirho(1600),
        phase_chirho,
        receipt_signer_key_chirho: pk_chirho(80),
        signature_chirho: sig_chirho(),
    }
}

fn intent_marker_chirho(
    phase_chirho: GeoGenesisPhaseChirho,
) -> AuthoritativeGeoGenesisIntentV1Chirho {
    AuthoritativeGeoGenesisIntentV1Chirho {
        schema_chirho: GeoGenesisIntentSchemaChirho::V1Chirho,
        instance_id_chirho: instance_chirho(),
        plan_ref_chirho: plan_ref_chirho(),
        prd_chirho: GeoPrdContentDigestChirho::new_chirho([3; 32]).unwrap(),
        ledger_plan_chirho: GeoLedgerRegenesisPlanDigestChirho::new_chirho([21; 32]).unwrap(),
        fresh_root_identity_chirho: GeoFreshRootIdentityChirho::new_chirho([22; 32]).unwrap(),
        consistency_group_chirho: GeoConsistencyGroupDigestChirho::new_chirho([23; 32]).unwrap(),
        tenant_root_chirho: GeoTenantRootIdentityChirho::new_chirho([24; 32]).unwrap(),
        roster_projection_chirho: GeoRosterProjectionDigestChirho::new_chirho([31; 32]).unwrap(),
        source_commit_chirho: GeoGitCommitIdChirho::new_chirho([2; 20]).unwrap(),
        rulings_chirho: resolved_rulings_chirho(),
        trust_profile_chirho:
            GeoGenesisTrustProfileChirho::SplitDedicatedPlanAndAcceptanceAuthoritiesChirho,
        intent_signer_key_chirho: pk_chirho(90),
        phase_chirho,
        signature_chirho: sig_chirho(),
    }
}

fn valid_gg_dispositions_chirho() -> GeoGgDispositionSetV1Chirho {
    let satisfied_chirho = |seed_chirho: u8| GeoGgDispositionV1Chirho {
        verdict_chirho: GeoGgVerdictChirho::VerifiedSatisfiedChirho,
        evidence_ref_chirho: GeoGgEvidenceRefChirho::new_chirho([seed_chirho; 32]).unwrap(),
    };
    GeoGgDispositionSetV1Chirho {
        gg1_chirho: satisfied_chirho(11),
        gg2_chirho: satisfied_chirho(12),
        gg3_chirho: satisfied_chirho(13),
        gg4_chirho: satisfied_chirho(14),
        gg5_chirho: satisfied_chirho(15),
        gg6_chirho: satisfied_chirho(16),
        gg7_chirho: satisfied_chirho(17),
        gg8_chirho: GeoGgDispositionV1Chirho {
            verdict_chirho: GeoGgVerdictChirho::StandingAdditiveChirho,
            evidence_ref_chirho: GeoGgEvidenceRefChirho::new_chirho([18; 32]).unwrap(),
        },
    }
}

fn observed_topology_chirho() -> GeoObservedTopologyV1Chirho {
    GeoObservedTopologyV1Chirho {
        voter_count_chirho: count_chirho(2),
        learner_count_chirho: count_chirho(1),
        provider_count_chirho: count_chirho(3),
        region_count_chirho: count_chirho(3),
        final_election_term_chirho: GeoElectionTermChirho::new_chirho(2).unwrap(),
        applied_roster_revision_chirho: GeoAppliedRosterRevisionChirho::new_chirho(4).unwrap(),
        applied_conf_index_chirho: GeoAppliedConfIndexChirho::new_chirho(1).unwrap(),
        member_set_chirho: GeoObservedMemberSetRefChirho::new_chirho([61; 32]).unwrap(),
        finalized_mirror_receipt_count_chirho: count_chirho(2),
        surviving_region_read_chirho:
            GeoSurvivingRegionReadVerdictChirho::SurvivingReadServedChirho,
        one_writer_chirho: GeoOneWriterVerdictChirho::OneWriterPreservedChirho,
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

fn root_publication_set_chirho() -> GeoRootPublicationSetV1Chirho {
    GeoRootPublicationSetV1Chirho {
        authoritative_root_chirho: publication_receipt_chirho(
            GeoGenesisPhaseChirho::RootPublishedChirho,
        ),
        member_admissions_chirho: vec![
            admission_chirho(1, 1),
            admission_chirho(2, 2),
            admission_chirho(3, 3),
        ],
    }
}

fn acceptance_packet_chirho(
    phase_chirho: GeoGenesisPhaseChirho,
    started_chirho: u32,
    accepted_chirho: u32,
) -> GeoGenesisAcceptancePacketV1Chirho {
    GeoGenesisAcceptancePacketV1Chirho {
        schema_chirho: GeoGenesisAcceptanceSchemaChirho::V1Chirho,
        instance_id_chirho: instance_chirho(),
        plan_ref_chirho: plan_ref_chirho(),
        intent_marker_set_chirho: GeoIntentMarkerSetRefChirho::new_chirho([55; 32]).unwrap(),
        root_publication_chirho: root_publication_set_chirho(),
        gg_dispositions_chirho: valid_gg_dispositions_chirho(),
        evidence_chirho: evidence_set_chirho(),
        observed_topology_chirho: observed_topology_chirho(),
        phase_chirho,
        hard_gates_chirho: GeoProductHardGatesClosedV1Chirho::all_closed_chirho(),
        started_at_chirho: utc_chirho(started_chirho),
        accepted_at_chirho: utc_chirho(accepted_chirho),
        trust_profile_chirho:
            GeoGenesisTrustProfileChirho::SplitDedicatedPlanAndAcceptanceAuthoritiesChirho,
        acceptance_signer_key_chirho: pk_chirho(200),
        signature_chirho: sig_chirho(),
    }
}

fn valid_marker_set_chirho() -> GeoIntentMarkerSetV1Chirho {
    GeoIntentMarkerSetV1Chirho {
        marker_ref_chirho: intent_ref_chirho(),
        operator_guard_chirho: marker_receipt_chirho(operator_holder_chirho()),
        member_markers_chirho: vec![
            marker_receipt_chirho(member_holder_chirho(1, 1)),
            marker_receipt_chirho(member_holder_chirho(2, 2)),
            marker_receipt_chirho(member_holder_chirho(3, 3)),
        ],
    }
}

// --- intent marker ---------------------------------------------------------------------------

#[test]
fn intent_marker_round_trips_and_companion_drops_signature_chirho() {
    let intent_chirho = intent_marker_chirho(GeoGenesisPhaseChirho::IntentReservedChirho);
    let bytes_chirho = canonical_record_bytes_chirho(&intent_chirho).unwrap();
    let parsed_chirho = parse_canonical_intent_chirho(&bytes_chirho).unwrap();
    assert_eq!(parsed_chirho, intent_chirho);

    let unsigned_chirho = intent_chirho.to_unsigned_chirho();
    let unsigned_text_chirho =
        String::from_utf8(canonical_record_bytes_chirho(&unsigned_chirho).unwrap()).unwrap();
    let signed_text_chirho = String::from_utf8(bytes_chirho).unwrap();
    assert!(signed_text_chirho.contains("\"signature_chirho\""));
    assert!(!unsigned_text_chirho.contains("\"signature_chirho\""));
}

#[test]
fn intent_marker_wrong_phase_refuses_chirho() {
    let intent_chirho = intent_marker_chirho(GeoGenesisPhaseChirho::RootPublishedChirho);
    assert_eq!(
        intent_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::PhaseRefusedChirho)
    );
}

// --- marker holder (internally tagged) -------------------------------------------------------

#[test]
fn marker_holder_round_trips_and_denies_unknown_chirho() {
    let holder_chirho = member_holder_chirho(5, 5);
    let text_chirho = serde_json::to_string(&holder_chirho).unwrap();
    assert!(text_chirho.contains("\"holder_kind_chirho\":\"member_chirho\""));
    let back_chirho: GeoMarkerHolderV1Chirho = serde_json::from_str(&text_chirho).unwrap();
    assert_eq!(back_chirho, holder_chirho);
    // Unknown field and unknown holder kind both refuse.
    let with_unknown_chirho = text_chirho.replacen('{', "{\"ghost_chirho\":1,", 1);
    assert!(serde_json::from_str::<GeoMarkerHolderV1Chirho>(&with_unknown_chirho).is_err());
    let unknown_kind_chirho = text_chirho.replace("\"member_chirho\"", "\"phantom_chirho\"");
    assert!(serde_json::from_str::<GeoMarkerHolderV1Chirho>(&unknown_kind_chirho).is_err());
}

// --- marker set structure --------------------------------------------------------------------

#[test]
fn valid_marker_set_validates_chirho() {
    valid_marker_set_chirho()
        .validate_structural_chirho()
        .unwrap();
}

#[test]
fn operator_slot_holding_member_refuses_holder_kind_chirho() {
    let mut set_chirho = valid_marker_set_chirho();
    set_chirho.operator_guard_chirho = marker_receipt_chirho(member_holder_chirho(1, 1));
    assert_eq!(
        set_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::MarkerHolderKindRefusedChirho)
    );
}

#[test]
fn member_slot_holding_operator_guard_refuses_holder_kind_chirho() {
    let mut set_chirho = valid_marker_set_chirho();
    set_chirho.member_markers_chirho[1] = marker_receipt_chirho(operator_holder_chirho());
    assert_eq!(
        set_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::MarkerHolderKindRefusedChirho)
    );
}

#[test]
fn unsorted_member_markers_refuse_chirho() {
    let mut set_chirho = valid_marker_set_chirho();
    set_chirho.member_markers_chirho.swap(0, 1);
    assert_eq!(
        set_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::MembersNotSortedChirho)
    );
}

#[test]
fn marker_set_below_count_band_refuses_chirho() {
    let mut set_chirho = valid_marker_set_chirho();
    set_chirho.member_markers_chirho.truncate(2);
    assert_eq!(
        set_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::SetCountOutOfRangeChirho)
    );
}

// --- publication + admission receipts --------------------------------------------------------

#[test]
fn publication_receipt_round_trips_and_wrong_phase_refuses_chirho() {
    let receipt_chirho = publication_receipt_chirho(GeoGenesisPhaseChirho::RootPublishedChirho);
    let bytes_chirho = canonical_record_bytes_chirho(&receipt_chirho).unwrap();
    let back_chirho: GeoGenesisPublicationReceiptV1Chirho =
        serde_json::from_slice(&bytes_chirho).unwrap();
    assert_eq!(back_chirho, receipt_chirho);
    receipt_chirho.validate_structural_chirho().unwrap();
    let _unsigned_chirho = receipt_chirho.to_unsigned_chirho();

    let wrong_chirho = publication_receipt_chirho(GeoGenesisPhaseChirho::HostedAcceptedChirho);
    assert_eq!(
        wrong_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::PhaseRefusedChirho)
    );
}

#[test]
fn admission_receipt_round_trips_and_companion_drops_signature_chirho() {
    let admission_chirho = admission_chirho(1, 1);
    let bytes_chirho = canonical_record_bytes_chirho(&admission_chirho).unwrap();
    let back_chirho: GeoGenesisMemberAdmissionReceiptV1Chirho =
        serde_json::from_slice(&bytes_chirho).unwrap();
    assert_eq!(back_chirho, admission_chirho);
    let unsigned_text_chirho = String::from_utf8(
        canonical_record_bytes_chirho(&admission_chirho.to_unsigned_chirho()).unwrap(),
    )
    .unwrap();
    assert!(!unsigned_text_chirho.contains("\"signature_chirho\""));
}

#[test]
fn root_publication_set_structure_checks_chirho() {
    root_publication_set_chirho()
        .validate_structural_chirho()
        .unwrap();
    // Unsorted admissions.
    let mut set_chirho = root_publication_set_chirho();
    set_chirho.member_admissions_chirho.swap(0, 2);
    assert_eq!(
        set_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::MembersNotSortedChirho)
    );
    // Duplicate node key across two admissions.
    let mut set_chirho = root_publication_set_chirho();
    set_chirho.member_admissions_chirho[1].node_key_chirho =
        set_chirho.member_admissions_chirho[0].node_key_chirho;
    assert_eq!(
        set_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::DuplicateMemberCoordinateChirho {
            coordinate_chirho: GeoMemberCoordinateChirho::NodeKeyChirho
        })
    );
    // Below the count band.
    let mut set_chirho = root_publication_set_chirho();
    set_chirho.member_admissions_chirho.truncate(2);
    assert_eq!(
        set_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::SetCountOutOfRangeChirho)
    );
}

// --- acceptance packet -----------------------------------------------------------------------

#[test]
fn acceptance_packet_round_trips_and_companion_drops_signature_chirho() {
    let packet_chirho =
        acceptance_packet_chirho(GeoGenesisPhaseChirho::HostedAcceptedChirho, 1000, 2000);
    let bytes_chirho = canonical_record_bytes_chirho(&packet_chirho).unwrap();
    let parsed_chirho = parse_canonical_acceptance_chirho(&bytes_chirho).unwrap();
    assert_eq!(parsed_chirho, packet_chirho);
    assert_eq!(
        canonical_record_bytes_chirho(&parsed_chirho).unwrap(),
        bytes_chirho
    );

    // The unsigned view drops the packet's OWN top-level signature, but the nested publication and
    // member-admission receipts are independently signed evidence and keep theirs — so the count of
    // signature fields falls by exactly one, it does not go to zero.
    let unsigned_chirho = packet_chirho.to_unsigned_chirho();
    let signed_text_chirho = String::from_utf8(bytes_chirho).unwrap();
    let unsigned_text_chirho =
        String::from_utf8(canonical_record_bytes_chirho(&unsigned_chirho).unwrap()).unwrap();
    let signed_signature_count_chirho = signed_text_chirho.matches("\"signature_chirho\"").count();
    let unsigned_signature_count_chirho =
        unsigned_text_chirho.matches("\"signature_chirho\"").count();
    assert_eq!(
        signed_signature_count_chirho - unsigned_signature_count_chirho,
        1
    );
    // The four nested receipt signatures (one publication + three admissions) survive.
    assert_eq!(unsigned_signature_count_chirho, 4);
}

#[test]
fn acceptance_packet_denies_unknown_and_duplicate_fields_chirho() {
    let packet_chirho =
        acceptance_packet_chirho(GeoGenesisPhaseChirho::HostedAcceptedChirho, 1000, 2000);
    let text_chirho =
        String::from_utf8(canonical_record_bytes_chirho(&packet_chirho).unwrap()).unwrap();
    let with_unknown_chirho = text_chirho.replacen('{', "{\"surprise_chirho\":1,", 1);
    assert_eq!(
        parse_canonical_acceptance_chirho(with_unknown_chirho.as_bytes()),
        Err(GeoGenesisRefusalChirho::MalformedChirho)
    );
    let with_dup_chirho = text_chirho.replacen('{', "{\"schema_chirho\":\"v1_chirho\",", 1);
    assert_eq!(
        parse_canonical_acceptance_chirho(with_dup_chirho.as_bytes()),
        Err(GeoGenesisRefusalChirho::MalformedChirho)
    );
}

#[test]
fn acceptance_packet_wrong_phase_refuses_chirho() {
    let packet_chirho =
        acceptance_packet_chirho(GeoGenesisPhaseChirho::RootPublishedChirho, 1000, 2000);
    assert_eq!(
        packet_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::PhaseRefusedChirho)
    );
}

#[test]
fn acceptance_packet_started_after_accepted_refuses_time_order_chirho() {
    let packet_chirho =
        acceptance_packet_chirho(GeoGenesisPhaseChirho::HostedAcceptedChirho, 2000, 1000);
    assert_eq!(
        packet_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::TimeOrderRefusedChirho)
    );
}
