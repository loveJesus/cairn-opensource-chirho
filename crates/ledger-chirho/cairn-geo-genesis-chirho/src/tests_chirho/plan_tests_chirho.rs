// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Plan arms: canonical round-trip, the unsigned companion, deny-unknown/duplicate, the by-field
//! unresolved refusal, and each structural validation failure by its own distinct reason.

use crate::digest_chirho::*;
use crate::error_chirho::{
    GeoGenesisRefusalChirho, GeoMemberCoordinateChirho, GeoRulingFieldChirho,
};
use crate::gate_chirho::GeoProductHardGatesClosedV1Chirho;
use crate::metadata_chirho::{
    GeoBuildTargetChirho, GeoCanaryKindChirho, GeoGgVerdictChirho, GeoMemberRoleChirho,
    GeoProviderChirho, GeoRegionChirho,
};
use crate::plan_chirho::*;
use crate::ruling_chirho::*;
use crate::scalar_chirho::*;
use crate::topology_chirho::*;

// --- fixture builders ------------------------------------------------------------------------

fn pk_chirho(seed_chirho: u8) -> GeoEd25519PublicKeyChirho {
    GeoEd25519PublicKeyChirho::new_chirho([seed_chirho; 32]).unwrap()
}
fn wg_chirho(seed_chirho: u8) -> GeoWireGuardPublicKeyChirho {
    GeoWireGuardPublicKeyChirho::new_chirho([seed_chirho; 32]).unwrap()
}
fn utc_chirho(minute_chirho: u32) -> GeoUtcMinuteChirho {
    GeoUtcMinuteChirho::new_chirho(minute_chirho).unwrap()
}
fn count_chirho(value_chirho: u16) -> GeoSmallCountChirho {
    GeoSmallCountChirho::new_chirho(value_chirho).unwrap()
}
fn port_chirho(value_chirho: u16) -> GeoPortChirho {
    GeoPortChirho::new_chirho(value_chirho).unwrap()
}
fn endpoint_chirho(
    seed_chirho: u8,
    last_chirho: u8,
    port_value_chirho: u16,
) -> GeoEndpointAddressV1Chirho {
    GeoEndpointAddressV1Chirho {
        address_chirho: GeoIpAddressChirho::Ipv4Chirho([10, seed_chirho, 0, last_chirho]),
        port_chirho: port_chirho(port_value_chirho),
    }
}

fn member_chirho(
    raft_chirho: u64,
    seed_chirho: u8,
    role_chirho: GeoMemberRoleChirho,
    provider_chirho: GeoProviderChirho,
    region_chirho: GeoRegionChirho,
    target_chirho: GeoBuildTargetChirho,
) -> GeoMemberPlanV1Chirho {
    GeoMemberPlanV1Chirho {
        role_chirho,
        raft_id_chirho: GeoRaftIdChirho::new_chirho(raft_chirho).unwrap(),
        node_key_chirho: pk_chirho(seed_chirho),
        wireguard_key_chirho: wg_chirho(seed_chirho.wrapping_add(100)),
        provider_chirho,
        region_chirho,
        build_target_chirho: target_chirho,
        endpoints_chirho: GeoEndpointSetV1Chirho {
            election_chirho: endpoint_chirho(seed_chirho, 1, 9001),
            mirror_chirho: endpoint_chirho(seed_chirho, 2, 9002),
            capability_read_chirho: endpoint_chirho(seed_chirho, 3, 9003),
        },
        custody_chirho: GeoNodeCustodyBindingV1Chirho {
            custody_key_chirho: pk_chirho(seed_chirho.wrapping_add(50)),
            verifier_refs_chirho: vec![
                GeoCustodyVerifierRefChirho::new_chirho([10 + seed_chirho; 32]).unwrap(),
                GeoCustodyVerifierRefChirho::new_chirho([20 + seed_chirho; 32]).unwrap(),
            ],
        },
        config_evidence_chirho: GeoNodeConfigEvidenceRefChirho::new_chirho([seed_chirho; 32])
            .unwrap(),
    }
}

fn build_member_chirho(
    seed_chirho: u8,
    target_chirho: GeoBuildTargetChirho,
) -> GeoMemberBuildEvidenceV1Chirho {
    GeoMemberBuildEvidenceV1Chirho {
        node_key_chirho: pk_chirho(seed_chirho),
        target_chirho,
        binary_sha256_chirho: GeoBinarySha256Chirho::new_chirho([seed_chirho; 32]).unwrap(),
        config_projection_chirho: GeoNodeConfigProjectionDigestChirho::new_chirho(
            [seed_chirho; 32],
        )
        .unwrap(),
        config_evidence_ref_chirho: GeoNodeConfigEvidenceRefChirho::new_chirho([seed_chirho; 32])
            .unwrap(),
        measured_at_chirho: utc_chirho(500),
        freshness_deadline_chirho: utc_chirho(5000),
    }
}

fn satisfied_gg_chirho(seed_chirho: u8) -> GeoGgDispositionV1Chirho {
    GeoGgDispositionV1Chirho {
        verdict_chirho: GeoGgVerdictChirho::VerifiedSatisfiedChirho,
        evidence_ref_chirho: GeoGgEvidenceRefChirho::new_chirho([seed_chirho; 32]).unwrap(),
    }
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

fn valid_plan_chirho() -> GeoGenesisPlanV1Chirho {
    GeoGenesisPlanV1Chirho {
        schema_chirho: GeoGenesisPlanSchemaChirho::V1Chirho,
        instance_id_chirho: GeoGenesisInstanceIdChirho::new_chirho([1; 32]).unwrap(),
        authored_at_chirho: utc_chirho(1000),
        execute_not_after_chirho: utc_chirho(1060),
        prd_chirho: GeoPrdBindingV1Chirho {
            reviewed_commit_chirho: GeoGitCommitIdChirho::new_chirho([2; 20]).unwrap(),
            prd_content_chirho: GeoPrdContentDigestChirho::new_chirho([3; 32]).unwrap(),
            gg_definition_set_chirho: GeoGgDefinitionSetDigestChirho::new_chirho([4; 32]).unwrap(),
            cf8_acceptance_set_chirho: GeoCf8AcceptanceSetDigestChirho::new_chirho([5; 32])
                .unwrap(),
        },
        rulings_chirho: resolved_rulings_chirho(),
        gg_dispositions_chirho: GeoGgDispositionSetV1Chirho {
            gg1_chirho: satisfied_gg_chirho(11),
            gg2_chirho: satisfied_gg_chirho(12),
            gg3_chirho: satisfied_gg_chirho(13),
            gg4_chirho: satisfied_gg_chirho(14),
            gg5_chirho: satisfied_gg_chirho(15),
            gg6_chirho: GeoGgDispositionV1Chirho {
                verdict_chirho: GeoGgVerdictChirho::VerifiedWiringReadyChirho,
                evidence_ref_chirho: GeoGgEvidenceRefChirho::new_chirho([16; 32]).unwrap(),
            },
            gg7_chirho: satisfied_gg_chirho(17),
            gg8_chirho: GeoGgDispositionV1Chirho {
                verdict_chirho: GeoGgVerdictChirho::StandingAdditiveChirho,
                evidence_ref_chirho: GeoGgEvidenceRefChirho::new_chirho([18; 32]).unwrap(),
            },
        },
        ledger_chirho: GeoLedgerGenesisBindingV1Chirho {
            ledger_regenesis_plan_chirho: GeoLedgerRegenesisPlanDigestChirho::new_chirho([21; 32])
                .unwrap(),
            fresh_root_identity_chirho: GeoFreshRootIdentityChirho::new_chirho([22; 32]).unwrap(),
            consistency_group_chirho: GeoConsistencyGroupDigestChirho::new_chirho([23; 32])
                .unwrap(),
            tenant_root_chirho: GeoTenantRootIdentityChirho::new_chirho([24; 32]).unwrap(),
            final_namespace_chirho: GeoLedgerFinalNamespaceDigestChirho::new_chirho([25; 32])
                .unwrap(),
            initial_epoch_chirho: 7,
        },
        topology_chirho: GeoTopologyPlanV1Chirho {
            roster_projection_chirho: GeoRosterProjectionDigestChirho::new_chirho([31; 32])
                .unwrap(),
            applied_roster_revision_chirho: GeoAppliedRosterRevisionChirho::new_chirho(4).unwrap(),
            required_applied_conf_index_chirho: GeoAppliedConfIndexChirho::new_chirho(0).unwrap(),
            minimum_provider_count_chirho: count_chirho(2),
            minimum_region_count_chirho: count_chirho(2),
            members_chirho: vec![
                member_chirho(
                    1,
                    1,
                    GeoMemberRoleChirho::VoterChirho,
                    GeoProviderChirho::HetznerChirho,
                    GeoRegionChirho::GermanyChirho,
                    GeoBuildTargetChirho::Aarch64UnknownLinuxGnuChirho,
                ),
                member_chirho(
                    2,
                    2,
                    GeoMemberRoleChirho::VoterChirho,
                    GeoProviderChirho::OvhChirho,
                    GeoRegionChirho::FranceChirho,
                    GeoBuildTargetChirho::Aarch64UnknownLinuxGnuChirho,
                ),
                member_chirho(
                    3,
                    3,
                    GeoMemberRoleChirho::LearnerChirho,
                    GeoProviderChirho::AwsChirho,
                    GeoRegionChirho::UnitedStatesChirho,
                    GeoBuildTargetChirho::X8664UnknownLinuxGnuChirho,
                ),
            ],
        },
        builds_chirho: GeoBuildEvidenceSetV1Chirho {
            reviewed_source_commit_chirho: GeoGitCommitIdChirho::new_chirho([2; 20]).unwrap(),
            members_chirho: vec![
                build_member_chirho(1, GeoBuildTargetChirho::Aarch64UnknownLinuxGnuChirho),
                build_member_chirho(2, GeoBuildTargetChirho::Aarch64UnknownLinuxGnuChirho),
                build_member_chirho(3, GeoBuildTargetChirho::X8664UnknownLinuxGnuChirho),
            ],
        },
        evidence_contracts_chirho: GeoEvidenceContractSetV1Chirho {
            item5_terminal_contract_chirho: GeoItem5TerminalContractDigestChirho::new_chirho(
                [41; 32],
            )
            .unwrap(),
            item5_certificate_contract_chirho: GeoItem5CertificateContractDigestChirho::new_chirho(
                [42; 32],
            )
            .unwrap(),
            item6_packet_contract_chirho: GeoItem6PacketContractDigestChirho::new_chirho([43; 32])
                .unwrap(),
            item7_mirror_contract_chirho: GeoItem7ContractRefChirho::new_chirho([44; 32]).unwrap(),
            item7_receipt_requirement_chirho: GeoItem7ReceiptRequirementV1Chirho {
                required_holder_count_chirho: count_chirho(2),
                required_domain_spread_chirho: count_chirho(2),
                closure_chirho: GeoItem7ClosureChirho::ManifestedPrefixClosureChirho,
                durability_chirho: GeoItem7DurabilityChirho::NativeDurabilityChirho,
                read_serving_chirho: GeoItem7ReadServingChirho::ReceiptGatedServingChirho,
            },
            canary_contract_chirho: GeoCanaryContractDigestChirho::new_chirho([45; 32]).unwrap(),
            cf7_packet_contract_chirho: GeoCf7PacketContractDigestChirho::new_chirho([46; 32])
                .unwrap(),
        },
        canary_chirho: GeoCanaryPlanV1Chirho {
            kind_chirho: GeoCanaryKindChirho::SyntheticCreditsCanaryV1Chirho,
            kind_ref_chirho: GeoSyntheticKindRefChirho::new_chirho([51; 32]).unwrap(),
            observation_window_minutes_chirho: count_chirho(30),
            real_subject_population_chirho: GeoCanaryRealSubjectPopulationChirho::ZeroChirho,
        },
        hard_gates_chirho: GeoProductHardGatesClosedV1Chirho::all_closed_chirho(),
        trust_profile_chirho:
            GeoGenesisTrustProfileChirho::SplitDedicatedPlanAndAcceptanceAuthoritiesChirho,
        plan_signer_key_chirho: pk_chirho(200),
        signature_chirho: GeoEd25519SignatureChirho::new_chirho([9; 64]).unwrap(),
    }
}

// --- round-trip + companion + wire refusals --------------------------------------------------

#[test]
fn valid_plan_round_trips_and_is_authorable_chirho() {
    let plan_chirho = valid_plan_chirho();
    plan_chirho.validate_authorable_chirho().unwrap();
    let bytes_chirho = plan_chirho.canonical_bytes_chirho().unwrap();
    let parsed_chirho = parse_canonical_plan_chirho(&bytes_chirho).unwrap();
    assert_eq!(parsed_chirho, plan_chirho);
    // Byte-identical canonical round-trip.
    assert_eq!(
        parsed_chirho.canonical_bytes_chirho().unwrap(),
        bytes_chirho
    );
}

#[test]
fn unsigned_companion_is_plan_minus_signature_chirho() {
    let plan_chirho = valid_plan_chirho();
    let unsigned_chirho = plan_chirho.to_unsigned_chirho();
    let unsigned_bytes_chirho = serde_json::to_vec(&unsigned_chirho).unwrap();
    let back_chirho: UnsignedGeoGenesisPlanV1Chirho =
        serde_json::from_slice(&unsigned_bytes_chirho).unwrap();
    assert_eq!(back_chirho, unsigned_chirho);
    // The signed bytes carry a signature; the unsigned canonical bytes do not.
    let signed_text_chirho =
        String::from_utf8(plan_chirho.canonical_bytes_chirho().unwrap()).unwrap();
    let unsigned_text_chirho = String::from_utf8(unsigned_bytes_chirho).unwrap();
    assert!(signed_text_chirho.contains("\"signature_chirho\""));
    assert!(!unsigned_text_chirho.contains("\"signature_chirho\""));
}

#[test]
fn plan_denies_unknown_and_duplicate_top_level_fields_chirho() {
    let bytes_chirho = valid_plan_chirho().canonical_bytes_chirho().unwrap();
    let text_chirho = String::from_utf8(bytes_chirho).unwrap();
    let with_unknown_chirho = text_chirho.replacen('{', "{\"surprise_chirho\":1,", 1);
    assert_eq!(
        parse_canonical_plan_chirho(with_unknown_chirho.as_bytes()),
        Err(GeoGenesisRefusalChirho::MalformedChirho)
    );
    let with_dup_chirho = text_chirho.replacen('{', "{\"schema_chirho\":\"v1_chirho\",", 1);
    assert_eq!(
        parse_canonical_plan_chirho(with_dup_chirho.as_bytes()),
        Err(GeoGenesisRefusalChirho::MalformedChirho)
    );
}

#[test]
fn noncanonical_bytes_refuse_even_when_parseable_chirho() {
    // A trailing space makes valid JSON that is not the canonical encoding.
    let mut bytes_chirho = valid_plan_chirho().canonical_bytes_chirho().unwrap();
    bytes_chirho.push(b' ');
    assert_eq!(
        parse_canonical_plan_chirho(&bytes_chirho),
        Err(GeoGenesisRefusalChirho::NotCanonicalChirho)
    );
}

// --- unresolved ruling refusal (parse-for-review still succeeds) -----------------------------

#[test]
fn unresolved_ruling_parses_for_review_but_refuses_authoring_chirho() {
    let mut plan_chirho = valid_plan_chirho();
    plan_chirho.rulings_chirho.cell_advance_chirho = GeoCellAdvanceRulingChirho::UnresolvedChirho;
    // Structural parse-for-review still succeeds (design section 4).
    let bytes_chirho = plan_chirho.canonical_bytes_chirho().unwrap();
    assert!(parse_canonical_plan_chirho(&bytes_chirho).is_ok());
    // Authoring refuses, by field.
    assert_eq!(
        plan_chirho.validate_authorable_chirho(),
        Err(GeoGenesisRefusalChirho::UnresolvedRulingChirho {
            field_chirho: GeoRulingFieldChirho::CellAdvanceChirho
        })
    );
}

#[test]
fn unresolved_trust_profile_refuses_authoring_by_field_chirho() {
    let mut plan_chirho = valid_plan_chirho();
    plan_chirho.trust_profile_chirho = GeoGenesisTrustProfileChirho::UnresolvedChirho;
    assert_eq!(
        plan_chirho.validate_authorable_chirho(),
        Err(GeoGenesisRefusalChirho::UnresolvedRulingChirho {
            field_chirho: GeoRulingFieldChirho::TrustProfileChirho
        })
    );
}

// --- each structural validation failure by its own distinct reason ---------------------------

#[test]
fn zero_initial_epoch_refuses_chirho() {
    let mut plan_chirho = valid_plan_chirho();
    plan_chirho.ledger_chirho.initial_epoch_chirho = 0;
    assert_eq!(
        plan_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::ZeroInitialEpochChirho)
    );
}

#[test]
fn member_count_below_band_refuses_chirho() {
    let mut plan_chirho = valid_plan_chirho();
    plan_chirho.topology_chirho.members_chirho.truncate(2);
    assert_eq!(
        plan_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::MemberCountOutOfRangeChirho)
    );
}

#[test]
fn unsorted_members_refuse_chirho() {
    let mut plan_chirho = valid_plan_chirho();
    plan_chirho.topology_chirho.members_chirho.swap(0, 1);
    assert_eq!(
        plan_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::MembersNotSortedChirho)
    );
}

#[test]
fn duplicate_node_key_refuses_by_coordinate_chirho() {
    let mut plan_chirho = valid_plan_chirho();
    let first_key_chirho = plan_chirho.topology_chirho.members_chirho[0].node_key_chirho;
    plan_chirho.topology_chirho.members_chirho[1].node_key_chirho = first_key_chirho;
    assert_eq!(
        plan_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::DuplicateMemberCoordinateChirho {
            coordinate_chirho: GeoMemberCoordinateChirho::NodeKeyChirho
        })
    );
}

#[test]
fn duplicate_endpoint_refuses_by_coordinate_chirho() {
    let mut plan_chirho = valid_plan_chirho();
    let shared_chirho = plan_chirho.topology_chirho.members_chirho[0]
        .endpoints_chirho
        .election_chirho;
    plan_chirho.topology_chirho.members_chirho[1]
        .endpoints_chirho
        .election_chirho = shared_chirho;
    assert_eq!(
        plan_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::DuplicateMemberCoordinateChirho {
            coordinate_chirho: GeoMemberCoordinateChirho::EndpointChirho
        })
    );
}

#[test]
fn endpoint_role_collision_within_member_refuses_chirho() {
    let mut plan_chirho = valid_plan_chirho();
    let election_chirho = plan_chirho.topology_chirho.members_chirho[0]
        .endpoints_chirho
        .election_chirho;
    plan_chirho.topology_chirho.members_chirho[0]
        .endpoints_chirho
        .mirror_chirho = election_chirho;
    assert_eq!(
        plan_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::EndpointRoleRefusedChirho)
    );
}

#[test]
fn zero_voters_refuses_role_count_chirho() {
    let mut plan_chirho = valid_plan_chirho();
    for member_chirho in &mut plan_chirho.topology_chirho.members_chirho {
        member_chirho.role_chirho = GeoMemberRoleChirho::LearnerChirho;
    }
    assert_eq!(
        plan_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::MemberRoleCountRefusedChirho)
    );
}

#[test]
fn insufficient_provider_spread_refuses_chirho() {
    let mut plan_chirho = valid_plan_chirho();
    plan_chirho.topology_chirho.minimum_provider_count_chirho = count_chirho(5);
    assert_eq!(
        plan_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::ProviderSpreadRefusedChirho)
    );
}

#[test]
fn insufficient_region_spread_refuses_chirho() {
    let mut plan_chirho = valid_plan_chirho();
    plan_chirho.topology_chirho.minimum_region_count_chirho = count_chirho(5);
    assert_eq!(
        plan_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::RegionSpreadRefusedChirho)
    );
}

#[test]
fn empty_custody_verifier_set_refuses_chirho() {
    let mut plan_chirho = valid_plan_chirho();
    plan_chirho.topology_chirho.members_chirho[0]
        .custody_chirho
        .verifier_refs_chirho
        .clear();
    assert_eq!(
        plan_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::CustodyBindingRefusedChirho)
    );
}

#[test]
fn build_member_mismatch_refuses_chirho() {
    let mut plan_chirho = valid_plan_chirho();
    plan_chirho.builds_chirho.members_chirho[1].node_key_chirho = pk_chirho(99);
    assert_eq!(
        plan_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::BuildMemberMismatchChirho)
    );
}

#[test]
fn build_target_mismatch_refuses_chirho() {
    let mut plan_chirho = valid_plan_chirho();
    plan_chirho.builds_chirho.members_chirho[0].target_chirho =
        GeoBuildTargetChirho::X8664UnknownLinuxGnuChirho;
    assert_eq!(
        plan_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::BuildTargetMismatchChirho)
    );
}

#[test]
fn gg_verdict_out_of_set_refuses_by_index_chirho() {
    let mut plan_chirho = valid_plan_chirho();
    plan_chirho.gg_dispositions_chirho.gg1_chirho.verdict_chirho =
        GeoGgVerdictChirho::StandingAdditiveChirho;
    assert_eq!(
        plan_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::GgVerdictRefusedChirho { gg_index_chirho: 1 })
    );
}

#[test]
fn plan_lifetime_over_ceiling_refuses_chirho() {
    let mut plan_chirho = valid_plan_chirho();
    plan_chirho.execute_not_after_chirho =
        utc_chirho(1000 + GEO_GENESIS_PLAN_MAX_LIFETIME_MINUTES_CHIRHO + 1);
    assert_eq!(
        plan_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::LifetimeRefusedChirho)
    );
}

#[test]
fn expiry_not_after_authoring_refuses_time_order_chirho() {
    let mut plan_chirho = valid_plan_chirho();
    plan_chirho.execute_not_after_chirho = plan_chirho.authored_at_chirho;
    assert_eq!(
        plan_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::TimeOrderRefusedChirho)
    );
}

#[test]
fn zero_canary_window_refuses_chirho() {
    let mut plan_chirho = valid_plan_chirho();
    plan_chirho.canary_chirho.observation_window_minutes_chirho = count_chirho(0);
    assert_eq!(
        plan_chirho.validate_structural_chirho(),
        Err(GeoGenesisRefusalChirho::CanaryRefusedChirho)
    );
}
