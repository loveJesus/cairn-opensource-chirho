// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Shared plan-side test fixtures: real Ed25519 keys, the two dedicated authority pins, a
//! structurally-complete ledger regenesis plan for the inward-edge digest reload, and an authored +
//! verified geo-genesis plan. The acceptance arms build a consistent packet on top of these.

use crate::author_chirho::author_plan_chirho;
use crate::digest_chirho::*;
use crate::gate_chirho::GeoProductHardGatesClosedV1Chirho;
use crate::metadata_chirho::*;
use crate::plan_chirho::*;
use crate::ruling_chirho::*;
use crate::scalar_chirho::*;
use crate::topology_chirho::*;
use crate::trust_chirho::{GeoGenesisTrustPinsChirho, GeoRoleSignerChirho, GeoSignerRoleChirho};
use crate::verify_chirho::{verify_plan_chirho, VerifiedGeoGenesisPlanChirho};
use cairn_ledger_regenesis_chirho::LedgerRegenesisPlanV1Chirho;
use ed25519_dalek::SigningKey;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const PLAN_AUTHORITY_SEED_CHIRHO: u8 = 201;
pub(crate) const ACCEPTANCE_AUTHORITY_SEED_CHIRHO: u8 = 202;
pub(crate) const MEMBER_SEEDS_CHIRHO: [u8; 3] = [1, 2, 3];
pub(crate) const PLAN_INSTANCE_SEED_CHIRHO: u8 = 1;

pub(crate) fn derived_pk_chirho(seed_chirho: u8) -> GeoEd25519PublicKeyChirho {
    let signing_key_chirho = SigningKey::from_bytes(&[seed_chirho; 32]);
    GeoEd25519PublicKeyChirho::new_chirho(*signing_key_chirho.verifying_key().as_bytes()).unwrap()
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
        "cairn-geo-82b-fixture-{nanos_chirho}-{ordinal_chirho}"
    ))
}

pub(crate) fn provision_signer_chirho(
    role_chirho: GeoSignerRoleChirho,
    seed_chirho: u8,
) -> GeoRoleSignerChirho {
    let pin_chirho = derived_pk_chirho(seed_chirho);
    let key_file_chirho = unique_temp_path_chirho();
    std::fs::write(&key_file_chirho, [seed_chirho; 32]).unwrap();
    GeoRoleSignerChirho::load_existing_pinned_chirho(role_chirho, &key_file_chirho, &pin_chirho)
        .unwrap()
}

pub(crate) fn split_pins_chirho() -> GeoGenesisTrustPinsChirho {
    GeoGenesisTrustPinsChirho::new_split_chirho(
        derived_pk_chirho(PLAN_AUTHORITY_SEED_CHIRHO),
        derived_pk_chirho(ACCEPTANCE_AUTHORITY_SEED_CHIRHO),
    )
    .unwrap()
}

/// A structurally-complete `LedgerRegenesisPlanV1Chirho` from canonical JSON; `variant` changes one
/// field so a mismatched reviewed plan yields a different digest.
pub(crate) fn ledger_plan_variant_chirho(variant_chirho: u64) -> LedgerRegenesisPlanV1Chirho {
    let json_chirho = format!(
        r#"{{
        "schema_chirho": "ledger-regenesis-plan-v1-chirho",
        "fresh_parent_chirho": "fresh", "staging_parent_chirho": "staging",
        "storage_namespace_chirho": "fresh/storage", "monitor_evidence_namespace_chirho": "fresh/monitor",
        "monitor_evidence_path_chirho": "monitor/evidence", "money_group_id_chirho": "grp",
        "cluster_id_chirho": "cl", "journal_path_chirho": "journal", "local_epoch_chirho": {variant_chirho},
        "kind_registry_path_chirho": "kinds", "kind_registry_id_chirho": "kr",
        "projection_registry_path_chirho": "proj", "projection_registry_id_chirho": "pr",
        "source_registry_path_chirho": "src", "source_registry_id_chirho": "sr",
        "projection_routes_chirho": [{{"projection_name_chirho": "p", "head_path_chirho": "h"}}],
        "monitor_cadence_ms_chirho": 1000, "issuer_principal_chirho": "iss",
        "initial_owner_chirho": "own", "kind_id_chirho": "k",
        "initial_policy_chirho": {{"unit_chirho": "u", "precision_chirho": 0,
            "mint_authority_chirho": {{"platform-policy-chirho": {{"max_supply_chirho": null}}}},
            "rounding_chirho": "exact-chirho", "shard_attachment_chirho": "s"}},
        "amended_policy_chirho": {{"unit_chirho": "u", "precision_chirho": 1,
            "mint_authority_chirho": {{"platform-policy-chirho": {{"max_supply_chirho": null}}}},
            "rounding_chirho": "exact-chirho", "shard_attachment_chirho": "s"}},
        "initial_mint_amount_chirho": 1, "genesis_physical_ms_chirho": 1, "mint_physical_ms_chirho": 2
    }}"#
    );
    serde_json::from_str(&json_chirho).unwrap()
}

pub(crate) fn ledger_digest_chirho(
    plan_chirho: &LedgerRegenesisPlanV1Chirho,
) -> GeoLedgerRegenesisPlanDigestChirho {
    GeoLedgerRegenesisPlanDigestChirho::from_canonical_ledger_regenesis_plan_chirho(plan_chirho)
        .unwrap()
}

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

/// A structurally valid, ruled plan whose signer key is `plan_signer_key` and ledger digest matches
/// `ledger_digest`. Signature is a placeholder; author it to sign.
fn unsigned_valid_plan_chirho(
    plan_signer_key_chirho: GeoEd25519PublicKeyChirho,
    ledger_digest_value_chirho: GeoLedgerRegenesisPlanDigestChirho,
) -> GeoGenesisPlanV1Chirho {
    let count_chirho = |value_chirho: u16| GeoSmallCountChirho::new_chirho(value_chirho).unwrap();
    let utc_chirho = |minute_chirho: u32| GeoUtcMinuteChirho::new_chirho(minute_chirho).unwrap();
    GeoGenesisPlanV1Chirho {
        schema_chirho: GeoGenesisPlanSchemaChirho::V1Chirho,
        instance_id_chirho: GeoGenesisInstanceIdChirho::new_chirho([PLAN_INSTANCE_SEED_CHIRHO; 32])
            .unwrap(),
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
                    MEMBER_SEEDS_CHIRHO[0],
                    GeoMemberRoleChirho::VoterChirho,
                    GeoProviderChirho::HetznerChirho,
                    GeoRegionChirho::GermanyChirho,
                    GeoBuildTargetChirho::Aarch64UnknownLinuxGnuChirho,
                ),
                member_chirho(
                    2,
                    MEMBER_SEEDS_CHIRHO[1],
                    GeoMemberRoleChirho::VoterChirho,
                    GeoProviderChirho::OvhChirho,
                    GeoRegionChirho::FranceChirho,
                    GeoBuildTargetChirho::Aarch64UnknownLinuxGnuChirho,
                ),
                member_chirho(
                    3,
                    MEMBER_SEEDS_CHIRHO[2],
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
                build_member_chirho(
                    MEMBER_SEEDS_CHIRHO[0],
                    GeoBuildTargetChirho::Aarch64UnknownLinuxGnuChirho,
                ),
                build_member_chirho(
                    MEMBER_SEEDS_CHIRHO[1],
                    GeoBuildTargetChirho::Aarch64UnknownLinuxGnuChirho,
                ),
                build_member_chirho(
                    MEMBER_SEEDS_CHIRHO[2],
                    GeoBuildTargetChirho::X8664UnknownLinuxGnuChirho,
                ),
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

/// Author and verify a valid plan, returning the verified token, its canonical bytes, and the
/// reviewed ledger plan. The custody pins are `split_pins_chirho`.
pub(crate) fn verified_valid_plan_chirho(
) -> (VerifiedGeoGenesisPlanChirho, LedgerRegenesisPlanV1Chirho) {
    let signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::PlanAuthorityChirho,
        PLAN_AUTHORITY_SEED_CHIRHO,
    );
    let ledger_plan_chirho = ledger_plan_variant_chirho(1);
    let candidate_chirho = unsigned_valid_plan_chirho(
        signer_chirho.public_key_chirho(),
        ledger_digest_chirho(&ledger_plan_chirho),
    );
    let signed_chirho =
        author_plan_chirho(candidate_chirho, &signer_chirho, &ledger_plan_chirho).unwrap();
    let bytes_chirho = signed_chirho.canonical_bytes_chirho().unwrap();
    let verified_chirho =
        verify_plan_chirho(&bytes_chirho, &split_pins_chirho(), &ledger_plan_chirho).unwrap();
    (verified_chirho, ledger_plan_chirho)
}

// ---------------------------------------------------------------------------------------------
// 8.3 shared fixtures: config-projection-bound plans + custody attestations.
// ---------------------------------------------------------------------------------------------

/// The throwaway fixture custody authority seed (ruling 1: attestations signed by a fixture authority).
pub(crate) const CUSTODY_AUTHORITY_SEED_CHIRHO: u8 = 210;

/// A member's fixture WireGuard public key (matches `member_chirho`'s `seed + 100` convention).
pub(crate) fn member_wireguard_key_chirho(seed_chirho: u8) -> GeoWireGuardPublicKeyChirho {
    GeoWireGuardPublicKeyChirho::new_chirho([seed_chirho.wrapping_add(100); 32]).unwrap()
}

/// The plan's fixture roster projection digest.
pub(crate) fn plan_roster_projection_chirho() -> GeoRosterProjectionDigestChirho {
    GeoRosterProjectionDigestChirho::new_chirho([31; 32]).unwrap()
}

/// Author + verify a valid plan whose per-member build `config_projection_chirho` digests are replaced
/// with `projections_chirho` (member order), so a config cross-bind can be proven end-to-end against a
/// plan that binds exactly the digests the safe config projections produce.
pub(crate) fn verified_plan_with_config_projections_chirho(
    projections_chirho: [GeoNodeConfigProjectionDigestChirho; 3],
) -> (VerifiedGeoGenesisPlanChirho, LedgerRegenesisPlanV1Chirho) {
    let signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::PlanAuthorityChirho,
        PLAN_AUTHORITY_SEED_CHIRHO,
    );
    let ledger_plan_chirho = ledger_plan_variant_chirho(1);
    let mut candidate_chirho = unsigned_valid_plan_chirho(
        signer_chirho.public_key_chirho(),
        ledger_digest_chirho(&ledger_plan_chirho),
    );
    for (index_chirho, projection_chirho) in projections_chirho.into_iter().enumerate() {
        candidate_chirho.builds_chirho.members_chirho[index_chirho].config_projection_chirho =
            projection_chirho;
    }
    let signed_chirho =
        author_plan_chirho(candidate_chirho, &signer_chirho, &ledger_plan_chirho).unwrap();
    let bytes_chirho = signed_chirho.canonical_bytes_chirho().unwrap();
    let verified_chirho =
        verify_plan_chirho(&bytes_chirho, &split_pins_chirho(), &ledger_plan_chirho).unwrap();
    (verified_chirho, ledger_plan_chirho)
}

/// A fixture custody-domain identity.
pub(crate) fn custody_domain_chirho(
    seed_chirho: u8,
) -> crate::custody_chirho::GeoCustodyDomainIdChirho {
    crate::custody_chirho::GeoCustodyDomainIdChirho::new_chirho([seed_chirho; 32]).unwrap()
}

/// Author a custody attestation under a fixture custody authority signer (design ruling 1).
pub(crate) fn author_custody_attestation_chirho(
    signer_chirho: &GeoRoleSignerChirho,
    domain_chirho: crate::custody_chirho::GeoCustodyDomainIdChirho,
    protected_key_chirho: GeoEd25519PublicKeyChirho,
    attestation_signer_key_chirho: GeoEd25519PublicKeyChirho,
) -> crate::custody_chirho::GeoCustodyAttestationV1Chirho {
    let unsigned_chirho = crate::custody_chirho::UnsignedGeoCustodyAttestationV1Chirho {
        schema_chirho: crate::custody_chirho::GeoCustodyAttestationSchemaChirho::V1Chirho,
        custody_domain_chirho: domain_chirho,
        protected_key_chirho,
        attestation_signer_key_chirho,
    };
    let bytes_chirho =
        crate::codec_chirho::canonical_record_bytes_chirho(&unsigned_chirho).unwrap();
    let signature_chirho = signer_chirho
        .sign_class_chirho(
            crate::trust_chirho::GeoGenesisMessageClassChirho::CustodyAttestationChirho,
            &bytes_chirho,
        )
        .unwrap();
    crate::custody_chirho::GeoCustodyAttestationV1Chirho {
        schema_chirho: crate::custody_chirho::GeoCustodyAttestationSchemaChirho::V1Chirho,
        custody_domain_chirho: domain_chirho,
        protected_key_chirho,
        attestation_signer_key_chirho,
        signature_chirho,
    }
}

/// Where the geo-genesis operator crate keeps the static fixtures its tests read.
pub(crate) fn operator_fixture_dir_chirho() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../host-chirho/cairn-geo-genesis-operator-chirho/tests/fixtures-chirho")
}

/// Writes the operator crate's plan fixtures from this crate's own valid plan: the signed plan's
/// canonical bytes, the reviewed ledger plan's canonical bytes, and the two pinned public keys with the
/// plan digest they verify to. Ignored: run it with `--ignored` only after a plan schema change.
#[test]
#[ignore = "regenerates the geo-genesis operator crate's plan fixtures; run explicitly after a schema change"]
fn export_operator_plan_fixtures_chirho() {
    let signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::PlanAuthorityChirho,
        PLAN_AUTHORITY_SEED_CHIRHO,
    );
    let ledger_plan_chirho = ledger_plan_variant_chirho(1);
    let candidate_chirho = unsigned_valid_plan_chirho(
        signer_chirho.public_key_chirho(),
        ledger_digest_chirho(&ledger_plan_chirho),
    );
    let plan_bytes_chirho =
        author_plan_chirho(candidate_chirho, &signer_chirho, &ledger_plan_chirho)
            .unwrap()
            .canonical_bytes_chirho()
            .unwrap();
    let verified_chirho = verify_plan_chirho(
        &plan_bytes_chirho,
        &split_pins_chirho(),
        &ledger_plan_chirho,
    )
    .unwrap();
    let dir_chirho = operator_fixture_dir_chirho();
    std::fs::create_dir_all(&dir_chirho).unwrap();
    std::fs::write(dir_chirho.join("plan-chirho.json"), &plan_bytes_chirho).unwrap();
    std::fs::write(
        dir_chirho.join("ledger-plan-chirho.json"),
        cairn_ledger_regenesis_chirho::canonical_plan_bytes_chirho(&ledger_plan_chirho).unwrap(),
    )
    .unwrap();
    let pins_chirho = serde_json::json!({
        "plan_authority_key_chirho": derived_pk_chirho(PLAN_AUTHORITY_SEED_CHIRHO),
        "acceptance_authority_key_chirho": derived_pk_chirho(ACCEPTANCE_AUTHORITY_SEED_CHIRHO),
        "plan_digest_chirho": verified_chirho.plan_digest_chirho(),
    });
    std::fs::write(
        dir_chirho.join("pins-chirho.json"),
        serde_json::to_vec_pretty(&pins_chirho).unwrap(),
    )
    .unwrap();
}
