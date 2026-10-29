// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The operator-private `GeoGenesisPlanV1Chirho` (design section 5), its explicit unsigned companion,
//! nested PRD/GG/ledger/canary/evidence-contract bindings, and the canonical parse + structural
//! validation. This is the wire law and its shape checks only; signing, custody, cross-artifact digest
//! binding, and the ruled-combination enforcement are 8.2b.

use crate::codec_chirho::{canonical_record_bytes_chirho, parse_canonical_chirho};
use crate::digest_chirho::{
    GeoCanaryContractDigestChirho, GeoCf7PacketContractDigestChirho,
    GeoCf8AcceptanceSetDigestChirho, GeoConsistencyGroupDigestChirho,
    GeoGgDefinitionSetDigestChirho, GeoGgEvidenceRefChirho,
    GeoItem5CertificateContractDigestChirho, GeoItem5TerminalContractDigestChirho,
    GeoItem6PacketContractDigestChirho, GeoItem7ContractRefChirho,
    GeoLedgerFinalNamespaceDigestChirho, GeoLedgerRegenesisPlanDigestChirho,
    GeoPrdContentDigestChirho, GeoSyntheticKindRefChirho,
};
use crate::error_chirho::{GeoGenesisRefusalChirho, GeoGenesisResultChirho, GeoRulingFieldChirho};
use crate::gate_chirho::GeoProductHardGatesClosedV1Chirho;
use crate::metadata_chirho::{GeoCanaryKindChirho, GeoGgVerdictChirho};
use crate::ruling_chirho::{
    GeoGenesisRulingSetV1Chirho, GeoGenesisTrustProfileChirho, GeoItem7ClosureChirho,
    GeoItem7DurabilityChirho, GeoItem7ReadServingChirho,
};
use crate::scalar_chirho::{
    GeoEd25519PublicKeyChirho, GeoEd25519SignatureChirho, GeoFreshRootIdentityChirho,
    GeoGenesisInstanceIdChirho, GeoGitCommitIdChirho, GeoSmallCountChirho,
    GeoTenantRootIdentityChirho, GeoUtcMinuteChirho,
};
use crate::topology_chirho::{
    earliest_build_deadline_chirho, validate_builds_chirho, validate_topology_chirho,
    GeoBuildEvidenceSetV1Chirho, GeoTopologyPlanV1Chirho,
};
use serde::{Deserialize, Serialize};

/// Fixed maximum authority window in minutes; a longer lifetime is a reviewed schema/policy change.
pub const GEO_GENESIS_PLAN_MAX_LIFETIME_MINUTES_CHIRHO: u32 = 1_440;

/// Closed plan schema token; unknown versions refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoGenesisPlanSchemaChirho {
    V1Chirho,
}

/// PRD and goal-gate source binding (design section 5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoPrdBindingV1Chirho {
    pub reviewed_commit_chirho: GeoGitCommitIdChirho,
    pub prd_content_chirho: GeoPrdContentDigestChirho,
    pub gg_definition_set_chirho: GeoGgDefinitionSetDigestChirho,
    pub cf8_acceptance_set_chirho: GeoCf8AcceptanceSetDigestChirho,
}

/// One GG disposition: a verdict plus a verified safe GG projection ref.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoGgDispositionV1Chirho {
    pub verdict_chirho: GeoGgVerdictChirho,
    pub evidence_ref_chirho: GeoGgEvidenceRefChirho,
}

/// The exact GG1-GG8 population; no omission or extra gate is representable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoGgDispositionSetV1Chirho {
    pub gg1_chirho: GeoGgDispositionV1Chirho,
    pub gg2_chirho: GeoGgDispositionV1Chirho,
    pub gg3_chirho: GeoGgDispositionV1Chirho,
    pub gg4_chirho: GeoGgDispositionV1Chirho,
    pub gg5_chirho: GeoGgDispositionV1Chirho,
    pub gg6_chirho: GeoGgDispositionV1Chirho,
    pub gg7_chirho: GeoGgDispositionV1Chirho,
    pub gg8_chirho: GeoGgDispositionV1Chirho,
}

impl GeoGgDispositionSetV1Chirho {
    /// Structural GG-verdict validation shared by the plan and the acceptance packet. The
    /// acceptance-time requirement that GG6 be `VerifiedSatisfiedChirho` (not merely wiring-ready) is
    /// an 8.2b acceptance equation, not enforced here.
    pub(crate) fn validate_chirho(&self) -> GeoGenesisResultChirho<()> {
        use GeoGgVerdictChirho::{
            StandingAdditiveChirho, VerifiedSatisfiedChirho, VerifiedWiringReadyChirho,
        };
        require_verdict_chirho(
            1,
            self.gg1_chirho.verdict_chirho,
            &[VerifiedSatisfiedChirho],
        )?;
        require_verdict_chirho(
            2,
            self.gg2_chirho.verdict_chirho,
            &[VerifiedSatisfiedChirho],
        )?;
        require_verdict_chirho(
            3,
            self.gg3_chirho.verdict_chirho,
            &[VerifiedSatisfiedChirho],
        )?;
        require_verdict_chirho(
            4,
            self.gg4_chirho.verdict_chirho,
            &[VerifiedSatisfiedChirho],
        )?;
        require_verdict_chirho(
            5,
            self.gg5_chirho.verdict_chirho,
            &[VerifiedSatisfiedChirho],
        )?;
        // GG6 keeps both allowed verdicts representable; binding the exact one to the GG6 ordering
        // ruling is 8.2b verify-time.
        require_verdict_chirho(
            6,
            self.gg6_chirho.verdict_chirho,
            &[VerifiedSatisfiedChirho, VerifiedWiringReadyChirho],
        )?;
        require_verdict_chirho(
            7,
            self.gg7_chirho.verdict_chirho,
            &[VerifiedSatisfiedChirho],
        )?;
        require_verdict_chirho(8, self.gg8_chirho.verdict_chirho, &[StandingAdditiveChirho])?;
        Ok(())
    }
}

fn require_verdict_chirho(
    gg_index_chirho: u8,
    verdict_chirho: GeoGgVerdictChirho,
    allowed_chirho: &[GeoGgVerdictChirho],
) -> GeoGenesisResultChirho<()> {
    if allowed_chirho.contains(&verdict_chirho) {
        Ok(())
    } else {
        Err(GeoGenesisRefusalChirho::GgVerdictRefusedChirho { gg_index_chirho })
    }
}

/// Fresh-root and ledger binding (design section 5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoLedgerGenesisBindingV1Chirho {
    pub ledger_regenesis_plan_chirho: GeoLedgerRegenesisPlanDigestChirho,
    pub fresh_root_identity_chirho: GeoFreshRootIdentityChirho,
    pub consistency_group_chirho: GeoConsistencyGroupDigestChirho,
    pub tenant_root_chirho: GeoTenantRootIdentityChirho,
    pub final_namespace_chirho: GeoLedgerFinalNamespaceDigestChirho,
    pub initial_epoch_chirho: u64,
}

/// Closed item-7 receipt requirement derived from the ruling (design sections 5.6, 6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoItem7ReceiptRequirementV1Chirho {
    pub required_holder_count_chirho: GeoSmallCountChirho,
    pub required_domain_spread_chirho: GeoSmallCountChirho,
    pub closure_chirho: GeoItem7ClosureChirho,
    pub durability_chirho: GeoItem7DurabilityChirho,
    pub read_serving_chirho: GeoItem7ReadServingChirho,
}

/// How future item-5/6/7/canary/CF7 evidence will be judged, committed at plan time without
/// fabricating the evidence itself (design section 5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoEvidenceContractSetV1Chirho {
    pub item5_terminal_contract_chirho: GeoItem5TerminalContractDigestChirho,
    pub item5_certificate_contract_chirho: GeoItem5CertificateContractDigestChirho,
    pub item6_packet_contract_chirho: GeoItem6PacketContractDigestChirho,
    pub item7_mirror_contract_chirho: GeoItem7ContractRefChirho,
    pub item7_receipt_requirement_chirho: GeoItem7ReceiptRequirementV1Chirho,
    pub canary_contract_chirho: GeoCanaryContractDigestChirho,
    pub cf7_packet_contract_chirho: GeoCf7PacketContractDigestChirho,
}

/// The real-subject population of the canary; `ZeroChirho` by type prevents real money/user data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoCanaryRealSubjectPopulationChirho {
    ZeroChirho,
}

/// Bounded synthetic canary plan (design section 5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoCanaryPlanV1Chirho {
    pub kind_chirho: GeoCanaryKindChirho,
    pub kind_ref_chirho: GeoSyntheticKindRefChirho,
    pub observation_window_minutes_chirho: GeoSmallCountChirho,
    pub real_subject_population_chirho: GeoCanaryRealSubjectPopulationChirho,
}

impl GeoCanaryPlanV1Chirho {
    fn validate_chirho(&self) -> GeoGenesisResultChirho<()> {
        if self.observation_window_minutes_chirho.get_chirho() == 0 {
            return Err(GeoGenesisRefusalChirho::CanaryRefusedChirho);
        }
        Ok(())
    }
}

/// The signed, operator-private genesis authority intent (design section 5.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoGenesisPlanV1Chirho {
    pub schema_chirho: GeoGenesisPlanSchemaChirho,
    pub instance_id_chirho: GeoGenesisInstanceIdChirho,
    pub authored_at_chirho: GeoUtcMinuteChirho,
    pub execute_not_after_chirho: GeoUtcMinuteChirho,
    pub prd_chirho: GeoPrdBindingV1Chirho,
    pub rulings_chirho: GeoGenesisRulingSetV1Chirho,
    pub gg_dispositions_chirho: GeoGgDispositionSetV1Chirho,
    pub ledger_chirho: GeoLedgerGenesisBindingV1Chirho,
    pub topology_chirho: GeoTopologyPlanV1Chirho,
    pub builds_chirho: GeoBuildEvidenceSetV1Chirho,
    pub evidence_contracts_chirho: GeoEvidenceContractSetV1Chirho,
    pub canary_chirho: GeoCanaryPlanV1Chirho,
    pub hard_gates_chirho: GeoProductHardGatesClosedV1Chirho,
    pub trust_profile_chirho: GeoGenesisTrustProfileChirho,
    pub plan_signer_key_chirho: GeoEd25519PublicKeyChirho,
    pub signature_chirho: GeoEd25519SignatureChirho,
}

/// The explicit unsigned companion (design section 10): every plan field except the signature, in the
/// same order. Signing serializes THIS struct's canonical bytes (8.2b), never a cleared field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedGeoGenesisPlanV1Chirho {
    pub schema_chirho: GeoGenesisPlanSchemaChirho,
    pub instance_id_chirho: GeoGenesisInstanceIdChirho,
    pub authored_at_chirho: GeoUtcMinuteChirho,
    pub execute_not_after_chirho: GeoUtcMinuteChirho,
    pub prd_chirho: GeoPrdBindingV1Chirho,
    pub rulings_chirho: GeoGenesisRulingSetV1Chirho,
    pub gg_dispositions_chirho: GeoGgDispositionSetV1Chirho,
    pub ledger_chirho: GeoLedgerGenesisBindingV1Chirho,
    pub topology_chirho: GeoTopologyPlanV1Chirho,
    pub builds_chirho: GeoBuildEvidenceSetV1Chirho,
    pub evidence_contracts_chirho: GeoEvidenceContractSetV1Chirho,
    pub canary_chirho: GeoCanaryPlanV1Chirho,
    pub hard_gates_chirho: GeoProductHardGatesClosedV1Chirho,
    pub trust_profile_chirho: GeoGenesisTrustProfileChirho,
    pub plan_signer_key_chirho: GeoEd25519PublicKeyChirho,
}

impl GeoGenesisPlanV1Chirho {
    /// The explicit unsigned view whose canonical bytes are the signing/verification input (8.2b).
    pub fn to_unsigned_chirho(&self) -> UnsignedGeoGenesisPlanV1Chirho {
        UnsignedGeoGenesisPlanV1Chirho {
            schema_chirho: self.schema_chirho,
            instance_id_chirho: self.instance_id_chirho,
            authored_at_chirho: self.authored_at_chirho,
            execute_not_after_chirho: self.execute_not_after_chirho,
            prd_chirho: self.prd_chirho,
            rulings_chirho: self.rulings_chirho,
            gg_dispositions_chirho: self.gg_dispositions_chirho,
            ledger_chirho: self.ledger_chirho,
            topology_chirho: self.topology_chirho.clone(),
            builds_chirho: self.builds_chirho.clone(),
            evidence_contracts_chirho: self.evidence_contracts_chirho,
            canary_chirho: self.canary_chirho,
            hard_gates_chirho: self.hard_gates_chirho,
            trust_profile_chirho: self.trust_profile_chirho,
            plan_signer_key_chirho: self.plan_signer_key_chirho,
        }
    }

    /// Canonical bytes of the complete signed plan.
    pub fn canonical_bytes_chirho(&self) -> GeoGenesisResultChirho<Vec<u8>> {
        canonical_record_bytes_chirho(self)
    }

    /// Structural validation that runs at parse/verify: schema is enforced by type; here we check the
    /// ledger epoch, topology, builds, timing, GG verdicts, and canary. Ruling resolution is NOT
    /// checked, so an unresolved plan can still be parsed for review (design section 4).
    pub fn validate_structural_chirho(&self) -> GeoGenesisResultChirho<()> {
        if self.ledger_chirho.initial_epoch_chirho == 0 {
            return Err(GeoGenesisRefusalChirho::ZeroInitialEpochChirho);
        }
        validate_topology_chirho(&self.topology_chirho)?;
        validate_builds_chirho(&self.builds_chirho, &self.topology_chirho)?;
        self.validate_timing_chirho()?;
        self.gg_dispositions_chirho.validate_chirho()?;
        self.canary_chirho.validate_chirho()?;
        Ok(())
    }

    /// The stronger gate authoring/signing must pass: structural validity PLUS resolved rulings and a
    /// resolved trust profile. Any unresolved choice refuses by field (design section 4, ruling 5).
    pub fn validate_authorable_chirho(&self) -> GeoGenesisResultChirho<()> {
        self.validate_structural_chirho()?;
        self.rulings_chirho.validate_resolved_chirho()?;
        if !self.trust_profile_chirho.is_resolved_chirho() {
            return Err(GeoGenesisRefusalChirho::UnresolvedRulingChirho {
                field_chirho: GeoRulingFieldChirho::TrustProfileChirho,
            });
        }
        Ok(())
    }

    fn validate_timing_chirho(&self) -> GeoGenesisResultChirho<()> {
        let authored_chirho = self.authored_at_chirho.get_chirho();
        let expiry_chirho = self.execute_not_after_chirho.get_chirho();
        let lifetime_chirho = expiry_chirho
            .checked_sub(authored_chirho)
            .filter(|window_chirho| *window_chirho >= 1)
            .ok_or(GeoGenesisRefusalChirho::TimeOrderRefusedChirho)?;
        if lifetime_chirho > GEO_GENESIS_PLAN_MAX_LIFETIME_MINUTES_CHIRHO {
            return Err(GeoGenesisRefusalChirho::LifetimeRefusedChirho);
        }
        if let Some(earliest_chirho) = earliest_build_deadline_chirho(&self.builds_chirho) {
            if expiry_chirho > earliest_chirho {
                return Err(GeoGenesisRefusalChirho::TimeOrderRefusedChirho);
            }
        }
        Ok(())
    }
}

/// Parse candidate bytes into a structurally valid plan for review: size bound, unknown/duplicate
/// refusal, exact canonical round-trip, and structural validation. Ruling resolution is deliberately
/// not enforced here; authoring/signing call `validate_authorable_chirho`.
pub fn parse_canonical_plan_chirho(
    bytes_chirho: &[u8],
) -> GeoGenesisResultChirho<GeoGenesisPlanV1Chirho> {
    let plan_chirho: GeoGenesisPlanV1Chirho = parse_canonical_chirho(bytes_chirho)?;
    plan_chirho.validate_structural_chirho()?;
    Ok(plan_chirho)
}
