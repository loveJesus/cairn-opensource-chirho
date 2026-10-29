// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Signer-boundary arms (8.2b, money/authority bar): a plan signed by the custody-pinned plan
//! authority verifies byte-identical; each field/digest/ruling/hard-gate mutation refuses by a
//! distinct reason; a non-pinned/self-selected signer refuses while the pinned one passes; cross-role
//! plan/acceptance signing refuses by message class; non-curve keys/signatures refuse. Every fixture
//! uses REAL Ed25519 keys derived from seeds, so curve-point validation is exercised, not bypassed.

use crate::author_chirho::author_plan_chirho;
use crate::digest_chirho::*;
use crate::error_chirho::{GeoGenesisRefusalChirho, GeoRulingFieldChirho};
use crate::gate_chirho::GeoProductHardGatesClosedV1Chirho;
use crate::metadata_chirho::*;
use crate::plan_chirho::*;
use crate::ruling_chirho::*;
use crate::scalar_chirho::*;
use crate::topology_chirho::*;
use crate::trust_chirho::{
    verify_class_signature_chirho, GeoGenesisMessageClassChirho, GeoGenesisTrustPinsChirho,
    GeoRoleSignerChirho, GeoSignerRoleChirho,
};
use crate::verify_chirho::{verify_plan_chirho, VerifiedGeoGenesisPlanChirho};
use cairn_ledger_regenesis_chirho::LedgerRegenesisPlanV1Chirho;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// --- key + signer provisioning ---------------------------------------------------------------

/// The public key of the Ed25519 keypair seeded by `[seed; 32]` — always a valid curve point.
fn derived_pk_chirho(seed_chirho: u8) -> GeoEd25519PublicKeyChirho {
    let signing_key_chirho = SigningKey::from_bytes(&[seed_chirho; 32]);
    GeoEd25519PublicKeyChirho::new_chirho(*signing_key_chirho.verifying_key().as_bytes()).unwrap()
}

fn unique_temp_path_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let ordinal_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-geo-82b-{label_chirho}-{nanos_chirho}-{ordinal_chirho}"
    ))
}

/// Write the 32-byte seed to a fresh regular file and return its path.
fn write_seed_file_chirho(seed_chirho: u8) -> PathBuf {
    let path_chirho = unique_temp_path_chirho("seed");
    std::fs::write(&path_chirho, [seed_chirho; 32]).unwrap();
    path_chirho
}

/// Provision a role-bound signer from an existing seed file, pinned to the seed's public key.
fn provision_signer_chirho(
    role_chirho: GeoSignerRoleChirho,
    seed_chirho: u8,
) -> GeoRoleSignerChirho {
    let pin_chirho = derived_pk_chirho(seed_chirho);
    let key_file_chirho = write_seed_file_chirho(seed_chirho);
    GeoRoleSignerChirho::load_existing_pinned_chirho(role_chirho, &key_file_chirho, &pin_chirho)
        .unwrap()
}

// The two dedicated authority seeds and a distinct member seed set.
const PLAN_AUTHORITY_SEED_CHIRHO: u8 = 201;
const ACCEPTANCE_AUTHORITY_SEED_CHIRHO: u8 = 202;

fn split_pins_chirho() -> GeoGenesisTrustPinsChirho {
    GeoGenesisTrustPinsChirho::new_split_chirho(
        derived_pk_chirho(PLAN_AUTHORITY_SEED_CHIRHO),
        derived_pk_chirho(ACCEPTANCE_AUTHORITY_SEED_CHIRHO),
    )
    .unwrap()
}

// --- ledger regenesis plan fixture (for the real inward-edge digest reload) -------------------

/// A structurally-complete `LedgerRegenesisPlanV1Chirho` deserialized from canonical JSON. Its exact
/// field values are irrelevant to the geo layer, which only rehashes its canonical bytes; `variant`
/// changes one field so a mismatched reviewed plan yields a different digest.
fn ledger_plan_variant_chirho(variant_chirho: u64) -> LedgerRegenesisPlanV1Chirho {
    let json_chirho = format!(
        r#"{{
        "schema_chirho": "ledger-regenesis-plan-v1-chirho",
        "fresh_parent_chirho": "fresh",
        "staging_parent_chirho": "staging",
        "storage_namespace_chirho": "fresh/storage",
        "monitor_evidence_namespace_chirho": "fresh/monitor",
        "monitor_evidence_path_chirho": "monitor/evidence",
        "money_group_id_chirho": "grp",
        "cluster_id_chirho": "cl",
        "journal_path_chirho": "journal",
        "local_epoch_chirho": {variant_chirho},
        "kind_registry_path_chirho": "kinds",
        "kind_registry_id_chirho": "kr",
        "projection_registry_path_chirho": "proj",
        "projection_registry_id_chirho": "pr",
        "source_registry_path_chirho": "src",
        "source_registry_id_chirho": "sr",
        "projection_routes_chirho": [{{"projection_name_chirho": "p", "head_path_chirho": "h"}}],
        "monitor_cadence_ms_chirho": 1000,
        "issuer_principal_chirho": "iss",
        "initial_owner_chirho": "own",
        "kind_id_chirho": "k",
        "initial_policy_chirho": {{
            "unit_chirho": "u", "precision_chirho": 0,
            "mint_authority_chirho": {{"platform-policy-chirho": {{"max_supply_chirho": null}}}},
            "rounding_chirho": "exact-chirho", "shard_attachment_chirho": "s"
        }},
        "amended_policy_chirho": {{
            "unit_chirho": "u", "precision_chirho": 1,
            "mint_authority_chirho": {{"platform-policy-chirho": {{"max_supply_chirho": null}}}},
            "rounding_chirho": "exact-chirho", "shard_attachment_chirho": "s"
        }},
        "initial_mint_amount_chirho": 1,
        "genesis_physical_ms_chirho": 1,
        "mint_physical_ms_chirho": 2
    }}"#
    );
    serde_json::from_str(&json_chirho).unwrap()
}

fn ledger_digest_chirho(
    plan_chirho: &LedgerRegenesisPlanV1Chirho,
) -> GeoLedgerRegenesisPlanDigestChirho {
    GeoLedgerRegenesisPlanDigestChirho::from_canonical_ledger_regenesis_plan_chirho(plan_chirho)
        .unwrap()
}

// --- geo plan fixture (valid, ruled, with real member keys) -----------------------------------

fn endpoint_chirho(
    seed_chirho: u8,
    last_chirho: u8,
    port_chirho: u16,
) -> GeoEndpointAddressV1Chirho {
    GeoEndpointAddressV1Chirho {
        address_chirho: GeoIpAddressChirho::Ipv4Chirho([10, seed_chirho, 0, last_chirho]),
        port_chirho: GeoPortChirho::new_chirho(port_chirho).unwrap(),
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
        node_key_chirho: derived_pk_chirho(seed_chirho),
        wireguard_key_chirho: GeoWireGuardPublicKeyChirho::new_chirho(
            [seed_chirho.wrapping_add(100); 32],
        )
        .unwrap(),
        provider_chirho,
        region_chirho,
        build_target_chirho: target_chirho,
        endpoints_chirho: GeoEndpointSetV1Chirho {
            election_chirho: endpoint_chirho(seed_chirho, 1, 9001),
            mirror_chirho: endpoint_chirho(seed_chirho, 2, 9002),
            capability_read_chirho: endpoint_chirho(seed_chirho, 3, 9003),
        },
        custody_chirho: GeoNodeCustodyBindingV1Chirho {
            custody_key_chirho: derived_pk_chirho(seed_chirho.wrapping_add(50)),
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
        node_key_chirho: derived_pk_chirho(seed_chirho),
        target_chirho,
        binary_sha256_chirho: GeoBinarySha256Chirho::new_chirho([seed_chirho; 32]).unwrap(),
        config_projection_chirho: GeoNodeConfigProjectionDigestChirho::new_chirho(
            [seed_chirho; 32],
        )
        .unwrap(),
        config_evidence_ref_chirho: GeoNodeConfigEvidenceRefChirho::new_chirho([seed_chirho; 32])
            .unwrap(),
        measured_at_chirho: GeoUtcMinuteChirho::new_chirho(500).unwrap(),
        freshness_deadline_chirho: GeoUtcMinuteChirho::new_chirho(5000).unwrap(),
    }
}

fn satisfied_gg_chirho(seed_chirho: u8) -> GeoGgDispositionV1Chirho {
    GeoGgDispositionV1Chirho {
        verdict_chirho: GeoGgVerdictChirho::VerifiedSatisfiedChirho,
        evidence_ref_chirho: GeoGgEvidenceRefChirho::new_chirho([seed_chirho; 32]).unwrap(),
    }
}

/// A structurally valid, ruled (split / phase-split / wiring-ready) plan whose embedded signer key is
/// `plan_signer_key_chirho` and whose ledger digest matches `ledger_digest_chirho`. Its signature is a
/// placeholder; callers author it to produce the real signature.
fn unsigned_valid_plan_chirho(
    plan_signer_key_chirho: GeoEd25519PublicKeyChirho,
    ledger_digest_value_chirho: GeoLedgerRegenesisPlanDigestChirho,
) -> GeoGenesisPlanV1Chirho {
    let count_chirho = |value_chirho: u16| GeoSmallCountChirho::new_chirho(value_chirho).unwrap();
    let utc_chirho = |minute_chirho: u32| GeoUtcMinuteChirho::new_chirho(minute_chirho).unwrap();
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
        rulings_chirho: GeoGenesisRulingSetV1Chirho {
            cell_advance_chirho: GeoCellAdvanceRulingChirho::WinnerForkWitnessOnDemandChirho,
            item7_chirho: GeoItem7RulingSetV1Chirho {
                replica_count_chirho: GeoItem7ReplicaCountChirho::N2ZoneChirho,
                membership_freshness_chirho:
                    GeoItem7MembershipFreshnessChirho::JoinedExactViewChirho,
                durability_chirho: GeoItem7DurabilityChirho::NativeDurabilityChirho,
                closure_chirho: GeoItem7ClosureChirho::ManifestedPrefixClosureChirho,
                failure_semantics_chirho:
                    GeoItem7FailureSemanticsChirho::PrepareCommitFinalizeChirho,
                read_serving_chirho: GeoItem7ReadServingChirho::ReceiptGatedServingChirho,
            },
            gg6_ordering_chirho: GeoGg6OrderingRulingChirho::WiringReadyThenHostedAcceptedChirho,
        },
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
            ledger_regenesis_plan_chirho: ledger_digest_value_chirho,
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
        plan_signer_key_chirho,
        signature_chirho: GeoEd25519SignatureChirho::new_chirho([0; 64]).unwrap(),
    }
}

/// Author a valid plan with the pinned plan-authority signer over the given ledger plan.
fn author_valid_plan_chirho(
    signer_chirho: &GeoRoleSignerChirho,
    ledger_plan_chirho: &LedgerRegenesisPlanV1Chirho,
) -> GeoGenesisPlanV1Chirho {
    let candidate_chirho = unsigned_valid_plan_chirho(
        signer_chirho.public_key_chirho(),
        ledger_digest_chirho(ledger_plan_chirho),
    );
    author_plan_chirho(candidate_chirho, signer_chirho, ledger_plan_chirho).unwrap()
}

// =============================================================================================
// Arm 1: a plan signed by the custody-pinned plan authority verifies byte-identical.
// =============================================================================================

#[test]
fn pinned_plan_authors_and_verifies_byte_identical_chirho() {
    let signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::PlanAuthorityChirho,
        PLAN_AUTHORITY_SEED_CHIRHO,
    );
    let pins_chirho = split_pins_chirho();
    let ledger_plan_chirho = ledger_plan_variant_chirho(1);

    let signed_chirho = author_valid_plan_chirho(&signer_chirho, &ledger_plan_chirho);
    let bytes_chirho = signed_chirho.canonical_bytes_chirho().unwrap();

    let verified_chirho =
        verify_plan_chirho(&bytes_chirho, &pins_chirho, &ledger_plan_chirho).unwrap();
    assert_eq!(verified_chirho.plan_chirho(), &signed_chirho);
    assert_eq!(
        verified_chirho.canonical_bytes_chirho(),
        bytes_chirho.as_slice()
    );
    assert_eq!(
        verified_chirho.plan_signer_key_chirho(),
        signer_chirho.public_key_chirho()
    );

    // Byte-identical re-verify of the emitted canonical bytes.
    let reverified_chirho = verify_plan_chirho(
        verified_chirho.canonical_bytes_chirho(),
        &pins_chirho,
        &ledger_plan_chirho,
    )
    .unwrap();
    assert_eq!(
        reverified_chirho.canonical_bytes_chirho(),
        bytes_chirho.as_slice()
    );
}

#[test]
fn verified_token_has_no_public_constructor_chirho() {
    // The private-token property is a compile-time fact: `VerifiedGeoGenesisPlanChirho` has private
    // fields and no public constructor, so this test can only OBTAIN one through `verify_plan_chirho`.
    // (A struct-literal here would fail to compile — that is the guarantee.)
    let signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::PlanAuthorityChirho,
        PLAN_AUTHORITY_SEED_CHIRHO,
    );
    let ledger_plan_chirho = ledger_plan_variant_chirho(1);
    let signed_chirho = author_valid_plan_chirho(&signer_chirho, &ledger_plan_chirho);
    let bytes_chirho = signed_chirho.canonical_bytes_chirho().unwrap();
    let token_chirho: VerifiedGeoGenesisPlanChirho =
        verify_plan_chirho(&bytes_chirho, &split_pins_chirho(), &ledger_plan_chirho).unwrap();
    assert_eq!(
        token_chirho.plan_chirho().schema_chirho,
        GeoGenesisPlanSchemaChirho::V1Chirho
    );
}

// =============================================================================================
// Arm 2: mutate each field/digest/ruling/hard-gate -> refuse by a DISTINCT reason.
// =============================================================================================

/// Re-author (honestly re-sign) after a mutation, returning either the authoring refusal or the
/// verify refusal. Because author and verify share the semantic gate, a semantic mutation refuses at
/// authoring by its own reason rather than collapsing into a signature failure.
fn reauthor_and_expect_refusal_chirho(
    mutate_chirho: impl FnOnce(&mut GeoGenesisPlanV1Chirho),
    ledger_plan_chirho: &LedgerRegenesisPlanV1Chirho,
) -> GeoGenesisRefusalChirho {
    let signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::PlanAuthorityChirho,
        PLAN_AUTHORITY_SEED_CHIRHO,
    );
    let mut candidate_chirho = unsigned_valid_plan_chirho(
        signer_chirho.public_key_chirho(),
        ledger_digest_chirho(ledger_plan_chirho),
    );
    mutate_chirho(&mut candidate_chirho);
    match author_plan_chirho(candidate_chirho, &signer_chirho, ledger_plan_chirho) {
        Err(refusal_chirho) => refusal_chirho,
        Ok(signed_chirho) => {
            let bytes_chirho = signed_chirho.canonical_bytes_chirho().unwrap();
            verify_plan_chirho(&bytes_chirho, &split_pins_chirho(), ledger_plan_chirho)
                .expect_err("a mutated plan must not verify")
        }
    }
}

#[test]
fn mutation_matrix_refuses_by_distinct_reason_chirho() {
    let ledger_plan_chirho = ledger_plan_variant_chirho(1);

    // Ledger-plan digest mismatch: bind a different ledger digest.
    assert_eq!(
        reauthor_and_expect_refusal_chirho(
            |plan_chirho| {
                plan_chirho.ledger_chirho.ledger_regenesis_plan_chirho =
                    ledger_digest_chirho(&ledger_plan_variant_chirho(999));
            },
            &ledger_plan_chirho,
        ),
        GeoGenesisRefusalChirho::LedgerPlanDigestMismatchChirho
    );

    // Ruled trust profile: not the split authority.
    assert_eq!(
        reauthor_and_expect_refusal_chirho(
            |plan_chirho| {
                plan_chirho.trust_profile_chirho =
                    GeoGenesisTrustProfileChirho::DedicatedGeoGenesisAuthorityForBothChirho;
            },
            &ledger_plan_chirho,
        ),
        GeoGenesisRefusalChirho::RuledTrustProfileRefusedChirho
    );

    // Ruled GG6 ordering: not the phase split.
    assert_eq!(
        reauthor_and_expect_refusal_chirho(
            |plan_chirho| {
                plan_chirho.rulings_chirho.gg6_ordering_chirho =
                    GeoGg6OrderingRulingChirho::StrictGg1ThroughGg7BeforeGenesisChirho;
            },
            &ledger_plan_chirho,
        ),
        GeoGenesisRefusalChirho::RuledGg6OrderingRefusedChirho
    );

    // GG6 verdict inconsistent with the phase-split ordering.
    assert_eq!(
        reauthor_and_expect_refusal_chirho(
            |plan_chirho| {
                plan_chirho.gg_dispositions_chirho.gg6_chirho.verdict_chirho =
                    GeoGgVerdictChirho::VerifiedSatisfiedChirho;
            },
            &ledger_plan_chirho,
        ),
        GeoGenesisRefusalChirho::Gg6VerdictOrderingMismatchChirho
    );

    // Unresolved ruling refuses by field.
    assert_eq!(
        reauthor_and_expect_refusal_chirho(
            |plan_chirho| {
                plan_chirho.rulings_chirho.cell_advance_chirho =
                    GeoCellAdvanceRulingChirho::UnresolvedChirho;
            },
            &ledger_plan_chirho,
        ),
        GeoGenesisRefusalChirho::UnresolvedRulingChirho {
            field_chirho: GeoRulingFieldChirho::CellAdvanceChirho
        }
    );

    // A structural field (zero epoch) surfaces its own reason through the author path.
    assert_eq!(
        reauthor_and_expect_refusal_chirho(
            |plan_chirho| plan_chirho.ledger_chirho.initial_epoch_chirho = 0,
            &ledger_plan_chirho,
        ),
        GeoGenesisRefusalChirho::ZeroInitialEpochChirho
    );
}

#[test]
fn reviewed_ledger_plan_mismatch_refuses_at_verify_chirho() {
    // Even a byte-identical honestly-signed plan refuses if the operator supplies the WRONG reviewed
    // ledger plan at verify time (the digest binding is checked against the real inward reload).
    let signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::PlanAuthorityChirho,
        PLAN_AUTHORITY_SEED_CHIRHO,
    );
    let ledger_plan_chirho = ledger_plan_variant_chirho(1);
    let signed_chirho = author_valid_plan_chirho(&signer_chirho, &ledger_plan_chirho);
    let bytes_chirho = signed_chirho.canonical_bytes_chirho().unwrap();

    assert_eq!(
        verify_plan_chirho(
            &bytes_chirho,
            &split_pins_chirho(),
            &ledger_plan_variant_chirho(2)
        ),
        Err(GeoGenesisRefusalChirho::LedgerPlanDigestMismatchChirho)
    );
}

#[test]
fn unknown_hard_gate_value_refuses_at_parse_chirho() {
    // Hard gates are false BY TYPE: an open/unknown wire value never parses (arm 15).
    let signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::PlanAuthorityChirho,
        PLAN_AUTHORITY_SEED_CHIRHO,
    );
    let ledger_plan_chirho = ledger_plan_variant_chirho(1);
    let signed_chirho = author_valid_plan_chirho(&signer_chirho, &ledger_plan_chirho);
    let text_chirho = String::from_utf8(signed_chirho.canonical_bytes_chirho().unwrap()).unwrap();
    let opened_chirho = text_chirho.replace("\"closed_chirho\"", "\"open_chirho\"");
    assert_ne!(opened_chirho, text_chirho);
    assert_eq!(
        verify_plan_chirho(
            opened_chirho.as_bytes(),
            &split_pins_chirho(),
            &ledger_plan_chirho
        ),
        Err(GeoGenesisRefusalChirho::MalformedChirho)
    );
}

// =============================================================================================
// Arm 3: a non-pinned / self-selected signer refuses; only the custody-pinned one passes.
// =============================================================================================

#[test]
fn non_pinned_signer_refuses_while_pinned_passes_chirho() {
    let ledger_plan_chirho = ledger_plan_variant_chirho(1);

    // A plan honestly signed by a DIFFERENT plan-authority key (its embedded key matches its own
    // signature — self-selected) refuses against the custody pins, which name the real authority.
    let rogue_signer_chirho =
        provision_signer_chirho(GeoSignerRoleChirho::PlanAuthorityChirho, 250);
    let rogue_plan_chirho = author_valid_plan_chirho(&rogue_signer_chirho, &ledger_plan_chirho);
    let rogue_bytes_chirho = rogue_plan_chirho.canonical_bytes_chirho().unwrap();
    assert_eq!(
        verify_plan_chirho(
            &rogue_bytes_chirho,
            &split_pins_chirho(),
            &ledger_plan_chirho
        ),
        Err(GeoGenesisRefusalChirho::CustodyPinMismatchChirho)
    );

    // The custody-pinned authority passes.
    let pinned_signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::PlanAuthorityChirho,
        PLAN_AUTHORITY_SEED_CHIRHO,
    );
    let pinned_plan_chirho = author_valid_plan_chirho(&pinned_signer_chirho, &ledger_plan_chirho);
    let pinned_bytes_chirho = pinned_plan_chirho.canonical_bytes_chirho().unwrap();
    assert!(verify_plan_chirho(
        &pinned_bytes_chirho,
        &split_pins_chirho(),
        &ledger_plan_chirho
    )
    .is_ok());
}

#[test]
fn tampered_signature_and_body_refuse_by_signature_chirho() {
    let signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::PlanAuthorityChirho,
        PLAN_AUTHORITY_SEED_CHIRHO,
    );
    let ledger_plan_chirho = ledger_plan_variant_chirho(1);
    let signed_chirho = author_valid_plan_chirho(&signer_chirho, &ledger_plan_chirho);

    // Flip a byte in the signature: the embedded key still matches the pin, but verify_strict rejects.
    let mut tampered_sig_chirho = signed_chirho.clone();
    let mut sig_bytes_chirho = *tampered_sig_chirho.signature_chirho.as_bytes_chirho();
    sig_bytes_chirho[10] ^= 0x01;
    tampered_sig_chirho.signature_chirho =
        GeoEd25519SignatureChirho::new_chirho(sig_bytes_chirho).unwrap();
    let tampered_sig_wire_chirho = tampered_sig_chirho.canonical_bytes_chirho().unwrap();
    assert_eq!(
        verify_plan_chirho(
            &tampered_sig_wire_chirho,
            &split_pins_chirho(),
            &ledger_plan_chirho
        ),
        Err(GeoGenesisRefusalChirho::SignatureRefusedChirho)
    );

    // Tamper the body WITHOUT re-signing: the unsigned bytes change, so the signature no longer covers
    // them. (Freshness is still valid, so this reaches the signature check.)
    let mut tampered_body_chirho = signed_chirho.clone();
    tampered_body_chirho.authored_at_chirho = GeoUtcMinuteChirho::new_chirho(1001).unwrap();
    let tampered_body_wire_chirho = tampered_body_chirho.canonical_bytes_chirho().unwrap();
    assert_eq!(
        verify_plan_chirho(
            &tampered_body_wire_chirho,
            &split_pins_chirho(),
            &ledger_plan_chirho
        ),
        Err(GeoGenesisRefusalChirho::SignatureRefusedChirho)
    );
}

// =============================================================================================
// Arm 4: cross-role plan/acceptance signing refuses by message class.
// =============================================================================================

#[test]
fn cross_role_signing_refuses_by_message_class_chirho() {
    let plan_signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::PlanAuthorityChirho,
        PLAN_AUTHORITY_SEED_CHIRHO,
    );
    let acceptance_signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::AcceptanceAuthorityChirho,
        ACCEPTANCE_AUTHORITY_SEED_CHIRHO,
    );
    let payload_chirho = b"any unsigned canonical bytes";

    // Plan authority cannot sign an acceptance-class message.
    assert_eq!(
        plan_signer_chirho.sign_class_chirho(
            GeoGenesisMessageClassChirho::AcceptanceChirho,
            payload_chirho
        ),
        Err(
            GeoGenesisRefusalChirho::CrossRoleMessageClassRefusedChirho {
                signer_role_chirho: GeoSignerRoleChirho::PlanAuthorityChirho,
                message_class_chirho: GeoGenesisMessageClassChirho::AcceptanceChirho,
            }
        )
    );

    // Acceptance authority cannot sign a plan-class message.
    assert_eq!(
        acceptance_signer_chirho
            .sign_class_chirho(GeoGenesisMessageClassChirho::PlanChirho, payload_chirho),
        Err(
            GeoGenesisRefusalChirho::CrossRoleMessageClassRefusedChirho {
                signer_role_chirho: GeoSignerRoleChirho::AcceptanceAuthorityChirho,
                message_class_chirho: GeoGenesisMessageClassChirho::PlanChirho,
            }
        )
    );

    // The acceptance authority cannot author a plan at all: `author_plan_chirho` signs the Plan class,
    // which its role does not own.
    let ledger_plan_chirho = ledger_plan_variant_chirho(1);
    let candidate_chirho = unsigned_valid_plan_chirho(
        acceptance_signer_chirho.public_key_chirho(),
        ledger_digest_chirho(&ledger_plan_chirho),
    );
    assert_eq!(
        author_plan_chirho(
            candidate_chirho,
            &acceptance_signer_chirho,
            &ledger_plan_chirho
        ),
        Err(
            GeoGenesisRefusalChirho::CrossRoleMessageClassRefusedChirho {
                signer_role_chirho: GeoSignerRoleChirho::AcceptanceAuthorityChirho,
                message_class_chirho: GeoGenesisMessageClassChirho::PlanChirho,
            }
        )
    );

    // Each role signs its OWN class.
    assert!(plan_signer_chirho
        .sign_class_chirho(GeoGenesisMessageClassChirho::PlanChirho, payload_chirho)
        .is_ok());
    assert!(acceptance_signer_chirho
        .sign_class_chirho(
            GeoGenesisMessageClassChirho::AcceptanceChirho,
            payload_chirho
        )
        .is_ok());
}

#[test]
fn domain_separation_makes_a_plan_signature_invalid_for_the_acceptance_class_chirho() {
    // A signature produced for one class must not verify for another, even under the same key. Sign a
    // payload as the Plan class, then try to verify it as the Acceptance class.
    let plan_signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::PlanAuthorityChirho,
        PLAN_AUTHORITY_SEED_CHIRHO,
    );
    let payload_chirho = b"one payload, two classes";
    let plan_signature_chirho = plan_signer_chirho
        .sign_class_chirho(GeoGenesisMessageClassChirho::PlanChirho, payload_chirho)
        .unwrap();
    let key_chirho = plan_signer_chirho.public_key_chirho();

    // Same class verifies.
    assert!(verify_class_signature_chirho(
        &key_chirho,
        GeoGenesisMessageClassChirho::PlanChirho,
        payload_chirho,
        &plan_signature_chirho,
    )
    .is_ok());

    // A different class over the same bytes and key refuses (distinct domain tag).
    assert_eq!(
        verify_class_signature_chirho(
            &key_chirho,
            GeoGenesisMessageClassChirho::AcceptanceChirho,
            payload_chirho,
            &plan_signature_chirho,
        ),
        Err(GeoGenesisRefusalChirho::SignatureRefusedChirho)
    );
}

// =============================================================================================
// Arm 5: non-curve-point keys and signatures refuse.
// =============================================================================================

/// A deterministic 32-byte value that is NOT a valid Ed25519 curve point.
fn non_curve_point_bytes_chirho() -> [u8; 32] {
    for seed_chirho in 0u8..=255 {
        let candidate_chirho = [seed_chirho; 32];
        if VerifyingKey::from_bytes(&candidate_chirho).is_err() {
            return candidate_chirho;
        }
    }
    panic!("expected some [n; 32] to be off the Ed25519 curve");
}

#[test]
fn non_curve_pin_and_key_refuse_chirho() {
    let off_curve_chirho =
        GeoEd25519PublicKeyChirho::new_chirho(non_curve_point_bytes_chirho()).unwrap();
    let valid_chirho = derived_pk_chirho(PLAN_AUTHORITY_SEED_CHIRHO);

    // A non-curve pin refuses at pins construction.
    assert_eq!(
        GeoGenesisTrustPinsChirho::new_split_chirho(off_curve_chirho, valid_chirho),
        Err(GeoGenesisRefusalChirho::TrustPinsRefusedChirho)
    );
    assert_eq!(
        GeoGenesisTrustPinsChirho::new_split_chirho(valid_chirho, off_curve_chirho),
        Err(GeoGenesisRefusalChirho::TrustPinsRefusedChirho)
    );

    // A non-curve expected key refuses at signature verification.
    let signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::PlanAuthorityChirho,
        PLAN_AUTHORITY_SEED_CHIRHO,
    );
    let signature_chirho = signer_chirho
        .sign_class_chirho(GeoGenesisMessageClassChirho::PlanChirho, b"payload")
        .unwrap();
    assert_eq!(
        verify_class_signature_chirho(
            &off_curve_chirho,
            GeoGenesisMessageClassChirho::PlanChirho,
            b"payload",
            &signature_chirho,
        ),
        Err(GeoGenesisRefusalChirho::NonCurvePointKeyChirho)
    );
}

#[test]
fn identical_split_pins_refuse_chirho() {
    // The split profile requires two DISTINCT keys; equal pins refuse (they are not two boundaries).
    let key_chirho = derived_pk_chirho(PLAN_AUTHORITY_SEED_CHIRHO);
    assert_eq!(
        GeoGenesisTrustPinsChirho::new_split_chirho(key_chirho, key_chirho),
        Err(GeoGenesisRefusalChirho::TrustPinsRefusedChirho)
    );
}

#[test]
fn non_curve_member_node_key_refuses_chirho() {
    // A plan carrying a member node key that is not a curve point refuses at verify (design 5.4).
    let signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::PlanAuthorityChirho,
        PLAN_AUTHORITY_SEED_CHIRHO,
    );
    let ledger_plan_chirho = ledger_plan_variant_chirho(1);
    let signed_chirho = author_valid_plan_chirho(&signer_chirho, &ledger_plan_chirho);

    // Replace one member node key with an off-curve value and honestly re-sign, so only the curve
    // check can refuse. Authoring itself curve-validates, so it refuses here.
    let off_curve_chirho =
        GeoEd25519PublicKeyChirho::new_chirho(non_curve_point_bytes_chirho()).unwrap();
    let mut candidate_chirho = signed_chirho;
    candidate_chirho.topology_chirho.members_chirho[0].node_key_chirho = off_curve_chirho;
    candidate_chirho.builds_chirho.members_chirho[0].node_key_chirho = off_curve_chirho;
    assert_eq!(
        author_plan_chirho(candidate_chirho, &signer_chirho, &ledger_plan_chirho),
        Err(GeoGenesisRefusalChirho::NonCurvePointKeyChirho)
    );
}

#[test]
fn non_curve_member_custody_key_refuses_chirho() {
    // A plan carrying a member CUSTODY key that is not a curve point refuses at verify. The custody
    // key is carried but not used to verify a signature here; it is curve-validated for structural
    // consistency alongside the node key (design 5.4), the symmetric case to the node-key arm above.
    let signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::PlanAuthorityChirho,
        PLAN_AUTHORITY_SEED_CHIRHO,
    );
    let ledger_plan_chirho = ledger_plan_variant_chirho(1);
    let signed_chirho = author_valid_plan_chirho(&signer_chirho, &ledger_plan_chirho);

    // Replace one member custody key with an off-curve value and honestly re-author. Nothing else is
    // touched (the custody key is not build-cross-checked or uniqueness-checked), so only the custody-
    // key curve check can refuse. Authoring itself curve-validates, so it refuses here.
    let off_curve_chirho =
        GeoEd25519PublicKeyChirho::new_chirho(non_curve_point_bytes_chirho()).unwrap();
    let mut candidate_chirho = signed_chirho;
    candidate_chirho.topology_chirho.members_chirho[0]
        .custody_chirho
        .custody_key_chirho = off_curve_chirho;
    assert_eq!(
        author_plan_chirho(candidate_chirho, &signer_chirho, &ledger_plan_chirho),
        Err(GeoGenesisRefusalChirho::NonCurvePointKeyChirho)
    );
}

// =============================================================================================
// Existing-key-only loader: never generates.
// =============================================================================================

#[test]
fn signer_load_refuses_missing_wrong_length_and_all_zero_without_creating_chirho() {
    let pin_chirho = derived_pk_chirho(PLAN_AUTHORITY_SEED_CHIRHO);

    // Absent file: refuses, creates nothing.
    let absent_chirho = unique_temp_path_chirho("absent");
    assert_eq!(
        GeoRoleSignerChirho::load_existing_pinned_chirho(
            GeoSignerRoleChirho::PlanAuthorityChirho,
            &absent_chirho,
            &pin_chirho,
        )
        .err(),
        Some(GeoGenesisRefusalChirho::ExistingSigningKeyRefusedChirho)
    );
    assert!(!absent_chirho.exists());

    // Wrong length: refuses.
    let short_chirho = unique_temp_path_chirho("short");
    std::fs::write(&short_chirho, [7u8; 16]).unwrap();
    assert_eq!(
        GeoRoleSignerChirho::load_existing_pinned_chirho(
            GeoSignerRoleChirho::PlanAuthorityChirho,
            &short_chirho,
            &pin_chirho,
        )
        .err(),
        Some(GeoGenesisRefusalChirho::ExistingSigningKeyRefusedChirho)
    );
    let _ = std::fs::remove_file(&short_chirho);

    // All-zero seed: refuses.
    let zero_chirho = unique_temp_path_chirho("zero");
    std::fs::write(&zero_chirho, [0u8; 32]).unwrap();
    assert_eq!(
        GeoRoleSignerChirho::load_existing_pinned_chirho(
            GeoSignerRoleChirho::PlanAuthorityChirho,
            &zero_chirho,
            &pin_chirho,
        )
        .err(),
        Some(GeoGenesisRefusalChirho::ExistingSigningKeyRefusedChirho)
    );
    let _ = std::fs::remove_file(&zero_chirho);

    // Right length but WRONG key: refuses with a pin mismatch, not a load error.
    let wrong_key_chirho = write_seed_file_chirho(9);
    assert_eq!(
        GeoRoleSignerChirho::load_existing_pinned_chirho(
            GeoSignerRoleChirho::PlanAuthorityChirho,
            &wrong_key_chirho,
            &pin_chirho,
        )
        .err(),
        Some(GeoGenesisRefusalChirho::CustodyPinMismatchChirho)
    );
    let _ = std::fs::remove_file(&wrong_key_chirho);
}
