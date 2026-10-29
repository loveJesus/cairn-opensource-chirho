// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Sealed request construction for the CF8 Phase C final-sink loss witness.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/cf8-canary-window-loss-sequence-chirho.md`.
//! Callers select only one fixed phase. Every money and authority coordinate comes from the
//! effective test-kind host configuration and its already verified kind registry.

use cairn_config_chirho::config_chirho::LedgerHostConfigChirho;
use cairn_kind_registry_chirho::chain_chirho::VerifiedRegistryChirho;
use cairn_ledger_log_chirho::journal_chirho::{AppendLegRequestChirho, AppendRequestChirho};
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerOpChirho, LegDeltaChirho};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

const TESTKIND_LOSS_WITNESS_AMOUNT_CHIRHO: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub(super) enum ResidentTestkindLossWitnessRoleChirho {
    CurrentWriterChirho,
    /// The same node committing again, later, in the SAME post-adoption canary generation.
    ///
    /// The first commit shows a node can write once; it cannot show the node still holds authority a
    /// measurable interval later. The canary window requires both, and its generation chain restarts
    /// at adoption, so only post-adoption observations can supply them. This role is that second
    /// observation, and it is a distinct append key rather than a repeat because
    /// `append_request_chirho` keys idempotency on exactly (phase, role).
    SustainedWriterChirho,
    DeposedSinkChirho,
}

impl ResidentTestkindLossWitnessRoleChirho {
    const fn as_key_token_chirho(self) -> &'static str {
        match self {
            Self::CurrentWriterChirho => "current-writer-chirho",
            Self::SustainedWriterChirho => "sustained-writer-chirho",
            Self::DeposedSinkChirho => "deposed-sink-chirho",
        }
    }
}

/// The only phase coordinate accepted from the test-kind operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResidentTestkindLossWitnessPhaseChirho {
    #[serde(rename = "leader-loss-chirho")]
    LeaderLossChirho,
    #[serde(rename = "node-loss-chirho")]
    NodeLossChirho,
    #[serde(rename = "region-loss-chirho")]
    RegionLossChirho,
    #[serde(rename = "heal-chirho")]
    HealChirho,
    #[serde(rename = "failback-chirho")]
    FailbackChirho,
}

impl ResidentTestkindLossWitnessPhaseChirho {
    pub const fn as_wire_token_chirho(self) -> &'static str {
        match self {
            Self::LeaderLossChirho => "leader-loss-chirho",
            Self::NodeLossChirho => "node-loss-chirho",
            Self::RegionLossChirho => "region-loss-chirho",
            Self::HealChirho => "heal-chirho",
            Self::FailbackChirho => "failback-chirho",
        }
    }

    pub fn from_wire_token_chirho(token_chirho: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(token_chirho.to_owned())).ok()
    }
}

/// Bounded committed cut returned by the full current-writer mutation envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidentTestkindLossWitnessCommitChirho {
    pub seq_chirho: u64,
    pub record_digest_chirho: DigestChirho,
    pub physical_ms_chirho: u64,
    pub logical_chirho: u32,
}

/// Exact outcomes the loss sequencer may distinguish without receiving authority coordinates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome_chirho", deny_unknown_fields)]
pub enum ResidentTestkindLossWitnessOutcomeChirho {
    #[serde(rename = "committed-chirho")]
    CommittedChirho {
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
        commit_chirho: ResidentTestkindLossWitnessCommitChirho,
    },
    #[serde(rename = "mirror-reconciliation-refused-chirho")]
    MirrorReconciliationRefusedChirho {
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    },
    #[serde(rename = "mirror-prepare-refused-chirho")]
    MirrorPrepareRefusedChirho {
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    },
    #[serde(rename = "deposed-sink-refused-chirho")]
    DeposedSinkRefusedChirho {
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    },
}

/// WHO opened the resident actor — the confinement axis for the CF8 loss-witness exemption.
///
/// The mode ORIGINATES from the opener, never from argument shape: only the dedicated single-node
/// normal-settlement dev door passes [`Self::NormalSettlementExemptionPermittedChirho`]; every other
/// door (production, shared-elector, compensation, capstone) passes
/// [`Self::MandatoryWitnessOrProductionChirho`]. A drill door therefore cannot inherit the exemption
/// by assembling the same composition arguments the dev door uses — the mode is a first-class
/// coordinate the opener selects, not something derived from the shape of what arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ResidentTestkindLossWitnessOpenerModeChirho {
    /// The dedicated single-node normal-settlement dev door. An exempt test-kind marker MAY skip the
    /// loss-witness — subject to the single-node + no-compensation consistency checks below.
    NormalSettlementExemptionPermittedChirho,
    /// Every other opener. An exempt marker reaching this mode is a drill trying to suppress its own
    /// witness and is refused; a non-exempt marker takes the ordinary mandatory-witness path.
    MandatoryWitnessOrProductionChirho,
}

/// Fixed refusal identities for the sealed loss-witness surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResidentTestkindLossWitnessRefusalChirho {
    #[serde(rename = "test-kind-config-required-chirho")]
    TestKindConfigRequiredChirho,
    #[serde(rename = "billing-kind-config-refused-chirho")]
    BillingKindConfigRefusedChirho,
    #[serde(rename = "billing-kind-policy-refused-chirho")]
    BillingKindPolicyRefusedChirho,
    #[serde(rename = "settlement-owner-refused-chirho")]
    SettlementOwnerRefusedChirho,
    #[serde(rename = "member-population-refused-chirho")]
    MemberPopulationRefusedChirho,
    #[serde(rename = "mutation-exemption-refused-chirho")]
    MutationExemptionRefusedChirho,
    #[serde(rename = "actor-unavailable-chirho")]
    ActorUnavailableChirho,
    #[serde(rename = "append-barrier-refused-chirho")]
    AppendBarrierRefusedChirho,
    #[serde(rename = "current-envelope-refused-chirho")]
    CurrentEnvelopeRefusedChirho,
    // The MIRROR family, split out of the generic envelope refusal above on 2026-08-17. That one
    // identity was the mapping for both `RefusedChirho` and `ConflictChirho`, and `RefusedChirho` was
    // itself produced from sixteen journal errors -- so a lawful mirror refusal reached the Clause 14
    // drill indistinguishable from a stale intent or an invalid tail signature. Measured consequence:
    // node loss and region loss reported a bare envelope refusal with no observed witness outcome and
    // nothing to act on. These three make the mirror cause legible without carrying free text, which
    // the Stops forbid in any report.
    //
    // Do not spell a sibling's wire token in this block: the drill's population guard counts these
    // renames as SUBSTRINGS of the enum body, so naming one in prose makes its count read 2 and fails
    // the guard. It caught exactly that while this split was being landed.
    // The RESIDENT-PATH family. Three hosted windows showed node loss and region loss failing at the
    // witness's first step with one unattributable identity; these say which kind of resident
    // condition refused, without carrying free text. The last one is a NAMED RESIDUAL, so "none of
    // the named groups" is itself a usable answer rather than a silent catch-all.
    //
    // (Sibling wire tokens are deliberately not spelled in this comment -- see the note on the mirror
    // block above: the drill's population guard counts renames as substrings of the enum body, so
    // naming one in prose makes its count read 2 and fails the guard. It caught that here too.)
    #[serde(rename = "envelope-readiness-canary-chirho")]
    EnvelopeReadinessCanaryRefusedChirho,
    // Window 4 showed node loss AND region loss both landing on the unnarrowed canary identity above,
    // so it now reports which coordinate moved. The split answers two different questions: a tail
    // coordinate means the journal ADVANCED past its canary evidence, a domain coordinate means the
    // epoch or group CHANGED underneath it. Field names only -- values never travel.
    #[serde(rename = "canary-tail-seq-chirho")]
    CanaryTailSeqRefusedChirho,
    #[serde(rename = "canary-tail-digest-chirho")]
    CanaryTailDigestRefusedChirho,
    #[serde(rename = "canary-consistency-group-chirho")]
    CanaryConsistencyGroupRefusedChirho,
    #[serde(rename = "envelope-gd7-hold-chirho")]
    EnvelopeGd7HoldRefusedChirho,
    #[serde(rename = "envelope-testkind-lane-chirho")]
    EnvelopeTestkindLaneRefusedChirho,
    #[serde(rename = "envelope-migration-fence-chirho")]
    EnvelopeMigrationFenceRefusedChirho,
    #[serde(rename = "envelope-fence-continuity-chirho")]
    EnvelopeFenceContinuityRefusedChirho,
    #[serde(rename = "envelope-inventory-bound-chirho")]
    EnvelopeInventoryBoundRefusedChirho,
    #[serde(rename = "envelope-authority-other-chirho")]
    EnvelopeAuthorityOtherRefusedChirho,
    #[serde(rename = "envelope-mirror-prepare-chirho")]
    EnvelopeMirrorPrepareRefusedChirho,
    #[serde(rename = "envelope-mirror-reconciliation-chirho")]
    EnvelopeMirrorReconciliationRefusedChirho,
    #[serde(rename = "envelope-mirror-evidence-pending-chirho")]
    EnvelopeMirrorEvidencePendingChirho,
    #[serde(rename = "current-authority-refused-chirho")]
    CurrentAuthorityRefusedChirho,
    #[serde(rename = "current-append-refused-chirho")]
    CurrentAppendRefusedChirho,
    #[serde(rename = "committed-evidence-pending-chirho")]
    CommittedEvidencePendingChirho,
    #[serde(rename = "deposed-sink-unexpected-refusal-chirho")]
    DeposedSinkUnexpectedRefusalChirho,
    #[serde(rename = "deposed-sink-unexpected-admission-chirho")]
    DeposedSinkUnexpectedAdmissionChirho,
    // A drill / shared-elector / compensation opener presented a test-kind config whose marker sets
    // the normal-settlement dev exemption. The exemption is confined by an EXPLICIT opener-selected
    // mode (only the dedicated single-node dev door permits it); any other opener reaching this with
    // an exempt marker is a drill attempting to suppress its own loss-witness, and fails closed here.
    #[serde(rename = "drill-exemption-refused-chirho")]
    DrillExemptionRefusedChirho,
}

impl fmt::Display for ResidentTestkindLossWitnessRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::TestKindConfigRequiredChirho => "Cf8LossWitnessTestKindConfigRequiredChirho",
            Self::BillingKindConfigRefusedChirho => "Cf8LossWitnessBillingKindConfigRefusedChirho",
            Self::BillingKindPolicyRefusedChirho => "Cf8LossWitnessBillingKindPolicyRefusedChirho",
            Self::SettlementOwnerRefusedChirho => "Cf8LossWitnessSettlementOwnerRefusedChirho",
            Self::MemberPopulationRefusedChirho => "Cf8LossWitnessMemberPopulationRefusedChirho",
            Self::MutationExemptionRefusedChirho => "Cf8LossWitnessMutationExemptionRefusedChirho",
            Self::ActorUnavailableChirho => "Cf8LossWitnessActorUnavailableChirho",
            Self::AppendBarrierRefusedChirho => "Cf8LossWitnessAppendBarrierRefusedChirho",
            Self::CurrentEnvelopeRefusedChirho => "Cf8LossWitnessCurrentEnvelopeRefusedChirho",
            Self::EnvelopeReadinessCanaryRefusedChirho => {
                "Cf8LossWitnessEnvelopeReadinessCanaryRefusedChirho"
            }
            Self::CanaryTailSeqRefusedChirho => "Cf8LossWitnessCanaryTailSeqRefusedChirho",
            Self::CanaryTailDigestRefusedChirho => "Cf8LossWitnessCanaryTailDigestRefusedChirho",
            Self::CanaryConsistencyGroupRefusedChirho => {
                "Cf8LossWitnessCanaryConsistencyGroupRefusedChirho"
            }
            Self::EnvelopeGd7HoldRefusedChirho => "Cf8LossWitnessEnvelopeGd7HoldRefusedChirho",
            Self::EnvelopeTestkindLaneRefusedChirho => {
                "Cf8LossWitnessEnvelopeTestkindLaneRefusedChirho"
            }
            Self::EnvelopeMigrationFenceRefusedChirho => {
                "Cf8LossWitnessEnvelopeMigrationFenceRefusedChirho"
            }
            Self::EnvelopeFenceContinuityRefusedChirho => {
                "Cf8LossWitnessEnvelopeFenceContinuityRefusedChirho"
            }
            Self::EnvelopeInventoryBoundRefusedChirho => {
                "Cf8LossWitnessEnvelopeInventoryBoundRefusedChirho"
            }
            Self::EnvelopeAuthorityOtherRefusedChirho => {
                "Cf8LossWitnessEnvelopeAuthorityOtherRefusedChirho"
            }
            Self::EnvelopeMirrorPrepareRefusedChirho => {
                "Cf8LossWitnessEnvelopeMirrorPrepareRefusedChirho"
            }
            Self::EnvelopeMirrorReconciliationRefusedChirho => {
                "Cf8LossWitnessEnvelopeMirrorReconciliationRefusedChirho"
            }
            Self::EnvelopeMirrorEvidencePendingChirho => {
                "Cf8LossWitnessEnvelopeMirrorEvidencePendingChirho"
            }
            Self::CurrentAuthorityRefusedChirho => "Cf8LossWitnessCurrentAuthorityRefusedChirho",
            Self::CurrentAppendRefusedChirho => "Cf8LossWitnessCurrentAppendRefusedChirho",
            Self::CommittedEvidencePendingChirho => "Cf8LossWitnessCommittedEvidencePendingChirho",
            Self::DeposedSinkUnexpectedRefusalChirho => {
                "Cf8LossWitnessDeposedSinkUnexpectedRefusalChirho"
            }
            Self::DeposedSinkUnexpectedAdmissionChirho => {
                "Cf8LossWitnessDeposedSinkUnexpectedAdmissionChirho"
            }
            Self::DrillExemptionRefusedChirho => "Cf8LossWitnessDrillExemptionRefusedChirho",
        })
    }
}

impl Error for ResidentTestkindLossWitnessRefusalChirho {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ResidentTestkindLossWitnessPlanChirho {
    payer_account_chirho: AccountIdChirho,
    settlement_account_chirho: AccountIdChirho,
    current_policy_ref_chirho: AssetKindRefChirho,
    registry_tail_chirho: DigestChirho,
}

/// Derive the immutable witness plan from verified startup inputs.
///
/// `Ok(None)` is the production posture (marker-less). A marker-less config never receives a partially
/// usable plan and therefore cannot be upgraded by retaining an attenuated handle from another actor.
///
/// The CF8 loss-witness exemption is confined by `opener_mode_chirho`, which the OPENER selects (only
/// the dedicated single-node normal-settlement dev door passes
/// [`ResidentTestkindLossWitnessOpenerModeChirho::NormalSettlementExemptionPermittedChirho`]). An
/// exempt marker reaching any other opener mode fails closed with
/// [`ResidentTestkindLossWitnessRefusalChirho::DrillExemptionRefusedChirho`], so a drill cannot
/// suppress its own witness by copying the flag. `election_reopen_owned_single_node_chirho` and
/// `compensation_provider_present_chirho` are CONSISTENCY defense-in-depth on top of the mode. A
/// non-exempt marker takes the unchanged mandatory-witness path (requires `postgres_effect_chirho`).
pub(super) fn derive_resident_testkind_loss_witness_plan_chirho(
    config_chirho: &LedgerHostConfigChirho,
    registry_chirho: &VerifiedRegistryChirho,
    opener_mode_chirho: ResidentTestkindLossWitnessOpenerModeChirho,
    election_reopen_owned_single_node_chirho: bool,
    compensation_provider_present_chirho: bool,
) -> std::result::Result<
    Option<ResidentTestkindLossWitnessPlanChirho>,
    ResidentTestkindLossWitnessRefusalChirho,
> {
    let Some(marker_chirho) = config_chirho.test_kind_chirho.as_ref() else {
        return Ok(None);
    };
    if marker_chirho.loss_witness_exempt_chirho {
        // Confined by WHO opened the actor, not by argument shape. The mode is the PRIMARY gate; the
        // single-node + no-compensation checks are consistency defense-in-depth. No conservation
        // restriction (a plain within-kind settlement carries no GD7 conservation obligation).
        if opener_mode_chirho
            != ResidentTestkindLossWitnessOpenerModeChirho::NormalSettlementExemptionPermittedChirho
        {
            return Err(ResidentTestkindLossWitnessRefusalChirho::DrillExemptionRefusedChirho);
        }
        if !election_reopen_owned_single_node_chirho {
            return Err(ResidentTestkindLossWitnessRefusalChirho::DrillExemptionRefusedChirho);
        }
        if compensation_provider_present_chirho {
            return Err(ResidentTestkindLossWitnessRefusalChirho::DrillExemptionRefusedChirho);
        }
        return Ok(None);
    }
    let billing_kind_chirho = config_chirho
        .postgres_effect_chirho
        .as_ref()
        .map(|postgres_chirho| AssetKindIdChirho(postgres_chirho.billing_kind_chirho.clone()))
        .ok_or(ResidentTestkindLossWitnessRefusalChirho::BillingKindConfigRefusedChirho)?;
    let projection_chirho = registry_chirho
        .kinds_chirho
        .get(&billing_kind_chirho)
        .ok_or(ResidentTestkindLossWitnessRefusalChirho::BillingKindPolicyRefusedChirho)?;
    let settlement_owner_chirho = projection_chirho
        .current_policy_chirho
        .settlement_owner_chirho
        .as_deref()
        .filter(|owner_chirho| !owner_chirho.is_empty())
        .ok_or(ResidentTestkindLossWitnessRefusalChirho::SettlementOwnerRefusedChirho)?;
    let matching_members_chirho = config_chirho
        .members_chirho
        .iter()
        .filter(|member_chirho| member_chirho.kind_id_chirho == billing_kind_chirho.0)
        .collect::<Vec<_>>();
    let settlement_members_chirho = matching_members_chirho
        .iter()
        .filter(|member_chirho| member_chirho.owner_chirho == settlement_owner_chirho)
        .collect::<Vec<_>>();
    let payer_members_chirho = matching_members_chirho
        .iter()
        .filter(|member_chirho| member_chirho.owner_chirho != settlement_owner_chirho)
        .collect::<Vec<_>>();
    if matching_members_chirho.len() != 2
        || settlement_members_chirho.len() != 1
        || payer_members_chirho.len() != 1
    {
        return Err(ResidentTestkindLossWitnessRefusalChirho::MemberPopulationRefusedChirho);
    }
    Ok(Some(ResidentTestkindLossWitnessPlanChirho {
        payer_account_chirho: AccountIdChirho::new_chirho(
            payer_members_chirho[0].owner_chirho.clone(),
            billing_kind_chirho.clone(),
        ),
        settlement_account_chirho: AccountIdChirho::new_chirho(
            settlement_members_chirho[0].owner_chirho.clone(),
            billing_kind_chirho,
        ),
        current_policy_ref_chirho: projection_chirho.current_ref_chirho.clone(),
        registry_tail_chirho: registry_chirho.tail_digest_chirho.clone(),
    }))
}

impl ResidentTestkindLossWitnessPlanChirho {
    pub(super) fn append_request_chirho(
        &self,
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
        role_chirho: ResidentTestkindLossWitnessRoleChirho,
    ) -> std::result::Result<AppendRequestChirho, ResidentTestkindLossWitnessRefusalChirho> {
        Ok(AppendRequestChirho {
            op_chirho: LedgerOpChirho::TransferChirho,
            legs_chirho: vec![
                AppendLegRequestChirho {
                    account_chirho: self.payer_account_chirho.clone(),
                    kind_policy_ref_chirho: self.current_policy_ref_chirho.clone(),
                    delta_chirho: LegDeltaChirho::DebitChirho,
                    amount_chirho: TESTKIND_LOSS_WITNESS_AMOUNT_CHIRHO,
                    counterpart_chirho: None,
                },
                AppendLegRequestChirho {
                    account_chirho: self.settlement_account_chirho.clone(),
                    kind_policy_ref_chirho: self.current_policy_ref_chirho.clone(),
                    delta_chirho: LegDeltaChirho::CreditChirho,
                    amount_chirho: TESTKIND_LOSS_WITNESS_AMOUNT_CHIRHO,
                    counterpart_chirho: None,
                },
            ],
            idempotency_key_chirho: format!(
                "cf8-loss-witness-{}-{}",
                phase_chirho.as_wire_token_chirho(),
                role_chirho.as_key_token_chirho(),
            ),
            provenance_chirho: Some(self.registry_tail_chirho.clone()),
            attribution_chirho: AttributionChirho::PlatformChirho,
        })
    }
}
