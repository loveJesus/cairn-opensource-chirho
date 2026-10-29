// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::super::store_chirho::{
    ActiveGd7ReconciliationChirho, CommittedGd7ReconciliationCheckpointChirho,
    Gd7ReconciliationStoreRefusalChirho,
};
use super::super::Gd7ManifestRefusalChirho;
use cairn_ledger_conservation_monitor_chirho::ConservationIncidentKindChirho;
use cairn_ledger_log_chirho::effect_record_fact_chirho::EffectRecordFactRefusalChirho;
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::record_chirho::EscrowControlChirho;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

pub const GD7_RECONCILIATION_PLAN_PAGE_SCHEMA_V1_CHIRHO: &str =
    "gd7-reconciliation-plan-page-v1-chirho";
pub const GD7_TERMINAL_MARKER_SCHEMA_V1_CHIRHO: &str = "gd7-terminal-marker-v1-chirho";
pub const MAX_GD7_RECONCILIATION_PLAN_PAGE_BYTES_CHIRHO: usize = 1024 * 1024;
pub const MAX_GD7_TERMINAL_MARKER_BYTES_CHIRHO: usize = 16 * 1024;
pub const MAX_GD7_EFFECT_INTENT_LINE_BYTES_CHIRHO: usize = 64 * 1024;
pub const MAX_GD7_EFFECT_TERMINAL_LINE_BYTES_CHIRHO: usize = 64 * 1024;

/// Read-only, point-addressed effect evidence with caller-enforced byte ceilings.
///
/// Implementations must inspect length before allocating/reading the body. The existing broad
/// effect-evidence port is intentionally not blanket-adapted because its loader has no bound.
pub trait Gd7EffectEvidenceReaderPortChirho {
    fn load_intent_line_bounded_chirho(
        &self,
        intent_ref_chirho: &DigestChirho,
        maximum_bytes_chirho: usize,
    ) -> anyhow::Result<Option<Vec<u8>>>;

    fn load_terminal_line_bounded_chirho(
        &self,
        outcome_ref_chirho: &DigestChirho,
        maximum_bytes_chirho: usize,
    ) -> anyhow::Result<Option<Vec<u8>>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7EffectLineageChirho {
    ForwardChirho,
    CompensationChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7TerminalDispositionChirho {
    CommittedFinalizeChirho,
    DefiniteNoEffectReleaseChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7EffectPlanObligationKindChirho {
    CommittedOnLosingForkChirho,
    InDoubtHoldOnLosingForkChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7EffectPlanObligationChirho {
    pub kind_chirho: Gd7EffectPlanObligationKindChirho,
    pub lineage_chirho: Gd7EffectLineageChirho,
    pub intent_ref_chirho: DigestChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_effect_key_chirho: Option<String>,
    pub reversion_contract_digest_chirho: DigestChirho,
    pub control_chirho: EscrowControlChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome_ref_chirho: Option<DigestChirho>,
    pub source_seq_chirho: u64,
    pub source_record_digest_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_marker_object_digest_chirho: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7PlanPageFactCountsChirho {
    pub ledger_only_record_count_chirho: u64,
    pub effect_hold_record_count_chirho: u64,
    pub effect_terminal_record_count_chirho: u64,
    pub resolved_hold_count_chirho: u64,
    pub unresolved_hold_count_chirho: u64,
    pub committed_terminal_count_chirho: u64,
    pub definite_no_effect_terminal_count_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7ReconciliationPlanPageChirho {
    pub schema_chirho: String,
    pub reconciliation_identity_digest_chirho: String,
    pub page_index_chirho: u64,
    pub manifest_page_ref_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub newer_plan_page_ref_chirho: Option<String>,
    pub manifest_record_count_chirho: u64,
    pub local_fact_counts_chirho: Gd7PlanPageFactCountsChirho,
    pub obligations_newest_first_chirho: Vec<Gd7EffectPlanObligationChirho>,
    pub terminal_marker_object_digests_newest_first_chirho: Vec<String>,
    pub cumulative_manifest_page_count_chirho: u64,
    pub cumulative_manifest_record_count_chirho: u64,
    pub cumulative_effect_obligation_count_chirho: u64,
    pub reached_anchor_chirho: bool,
}

impl Gd7ReconciliationPlanPageChirho {
    pub fn page_index_chirho(&self) -> u64 {
        self.page_index_chirho
    }

    pub fn manifest_page_ref_chirho(&self) -> &str {
        &self.manifest_page_ref_chirho
    }

    pub fn newer_plan_page_ref_chirho(&self) -> Option<&str> {
        self.newer_plan_page_ref_chirho.as_deref()
    }

    pub fn obligations_newest_first_chirho(&self) -> &[Gd7EffectPlanObligationChirho] {
        &self.obligations_newest_first_chirho
    }

    pub fn cumulative_effect_obligation_count_chirho(&self) -> u64 {
        self.cumulative_effect_obligation_count_chirho
    }

    pub fn reached_anchor_chirho(&self) -> bool {
        self.reached_anchor_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGd7ReconciliationPlanPageChirho {
    pub(crate) object_digest_chirho: String,
    pub(crate) page_chirho: Gd7ReconciliationPlanPageChirho,
}

impl VerifiedGd7ReconciliationPlanPageChirho {
    pub fn object_digest_chirho(&self) -> &str {
        &self.object_digest_chirho
    }

    pub fn page_chirho(&self) -> &Gd7ReconciliationPlanPageChirho {
        &self.page_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7TerminalMarkerChirho {
    pub schema_chirho: String,
    pub reconciliation_identity_digest_chirho: String,
    pub intent_ref_chirho: DigestChirho,
    pub lineage_chirho: Gd7EffectLineageChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_effect_key_chirho: Option<String>,
    pub control_chirho: EscrowControlChirho,
    pub outcome_ref_chirho: DigestChirho,
    pub disposition_chirho: Gd7TerminalDispositionChirho,
    pub terminal_seq_chirho: u64,
    pub terminal_record_digest_chirho: String,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGd7TerminalMarkerChirho {
    pub(crate) object_digest_chirho: String,
    pub(crate) marker_chirho: Gd7TerminalMarkerChirho,
}

impl VerifiedGd7TerminalMarkerChirho {
    pub fn object_digest_chirho(&self) -> &str {
        &self.object_digest_chirho
    }

    pub fn marker_chirho(&self) -> &Gd7TerminalMarkerChirho {
        &self.marker_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gd7PlanPageDriveOutcomeChirho {
    CommittedChirho {
        checkpoint_chirho: CommittedGd7ReconciliationCheckpointChirho,
        plan_page_chirho: Box<VerifiedGd7ReconciliationPlanPageChirho>,
    },
    AwaitingManifestPageChirho(ActiveGd7ReconciliationChirho),
    AlreadyAdvancedChirho(ActiveGd7ReconciliationChirho),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gd7PlanRefusalChirho {
    TenantMigrationSourceFenceActiveChirho,
    InvalidReferenceChirho,
    NoActiveReconciliationChirho,
    StaleCheckpointChirho,
    InvalidPhaseChirho,
    NoUnreducedManifestPageChirho,
    InvalidPageShapeChirho,
    MalformedPlanPageChirho,
    NonCanonicalPlanPageChirho,
    OversizedPlanPageChirho,
    MalformedTerminalMarkerChirho,
    NonCanonicalTerminalMarkerChirho,
    OversizedTerminalMarkerChirho,
    InvalidTerminalMarkerSignatureChirho,
    MissingTerminalMarkerChirho,
    InvalidLosingRecordEncodingChirho,
    InvalidLosingRecordSignatureChirho,
    MissingObjectChirho,
    ObjectDigestMismatchChirho,
    ImmutableCollisionChirho,
    ArithmeticOverflowChirho,
    MissingIntentEvidenceChirho,
    IntentEvidenceUnavailableChirho,
    InvalidIntentEvidenceChirho,
    IntentEvidenceMismatchChirho,
    MissingTerminalEvidenceChirho,
    TerminalEvidenceUnavailableChirho,
    InvalidTerminalEvidenceChirho,
    OperatorRosterRefusalChirho(String),
    TerminalEvidenceMismatchChirho,
    EffectLineageMismatchChirho,
    TerminalMarkerMismatchChirho,
    ObligationNotInSealedPlanChirho,
    /// A per-page cumulative count diverged from the running total during the manifest walk.
    ///
    /// The payload is the exact plan page ref that introduced the divergence, so a mismatched
    /// chain is located at its page rather than reported as an unattributed total.
    CumulativeDivergenceAtPlanPageChirho(String),
    /// One enumerated obligation reached no satisfying terminal outcome.
    ///
    /// The payload is that obligation's mint identity digest, so an operator learns *which*
    /// obligation blocks convergence rather than only that something does.
    UnconvergedObligationChirho(String),
    /// A durable processing row was found under one obligation's mint identity but describes a
    /// different obligation. The payload is the mint identity digest that was looked up.
    ObligationStateSubjectMismatchChirho(String),
    /// The conservation source could not produce a verified snapshot at this cut.
    ///
    /// Fail-closed by construction: no snapshot means no measured conservation, which means no
    /// certificate — never a certificate that silently skipped the check.
    ConservationSnapshotUnavailableChirho,
    /// The conservation snapshot was not signed by the expected verification root.
    ///
    /// Deliberately distinct from [`Self::ConservationIncidentChirho`]: "not authentic" and
    /// "authentic but does not conserve money" are different facts, and a tamper arm must be able
    /// to prove which one refused it.
    InvalidConservationSnapshotSignatureChirho,
    /// A signature-verified conservation snapshot failed a CF4 conservation law.
    ///
    /// The payload is the checker's own incident kind, so the refusal names the law BY TYPE — a
    /// drift law and each structural law stay distinguishable rather than collapsing into one
    /// stringly-typed "conservation failed".
    ConservationIncidentChirho(Box<ConservationIncidentKindChirho>),
    RecordFactChirho(EffectRecordFactRefusalChirho),
    ManifestChirho(Gd7ManifestRefusalChirho),
    StoreChirho(Gd7ReconciliationStoreRefusalChirho),
    SerializationChirho,
    SigningChirho,
    StorageChirho,
}

/// Human-readable name of the CF4 conservation law an incident reports.
///
/// Prose only. Callers that must ACT on an incident match the typed
/// [`ConservationIncidentKindChirho`] payload instead — this exists so a log line says which
/// equation broke, not so anyone parses it back.
fn conservation_law_name_chirho(
    incident_kind_chirho: &ConservationIncidentKindChirho,
) -> &'static str {
    match incident_kind_chirho {
        ConservationIncidentKindChirho::DomainDriftChirho { .. } => "domain drift",
        ConservationIncidentKindChirho::GlobalKindDriftChirho { .. } => "global kind drift",
        ConservationIncidentKindChirho::DuplicateDomainKindRollupChirho { .. } => {
            "duplicate domain-kind rollup"
        }
        ConservationIncidentKindChirho::DuplicateGlobalKindSupplyChirho { .. } => {
            "duplicate global-kind supply"
        }
        ConservationIncidentKindChirho::MissingGlobalKindSupplyChirho { .. } => {
            "missing global-kind supply"
        }
        ConservationIncidentKindChirho::GlobalSupplyWithoutDomainRollupChirho { .. } => {
            "global supply without domain rollup"
        }
        ConservationIncidentKindChirho::ArithmeticOverflowChirho => {
            "conservation arithmetic overflow"
        }
    }
}

impl fmt::Display for Gd7PlanRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Located refusals render their coordinate: the payloads are content addresses and mint
        // identity digests, so naming them tells an operator WHERE to look without disclosing
        // any obligation content.
        match self {
            Self::CumulativeDivergenceAtPlanPageChirho(plan_page_ref_chirho) => {
                return write!(
                    formatter_chirho,
                    "GD7 plan page cumulative count diverged at page {plan_page_ref_chirho}"
                )
            }
            Self::UnconvergedObligationChirho(mint_identity_digest_chirho) => {
                return write!(
                    formatter_chirho,
                    "GD7 obligation {mint_identity_digest_chirho} has no satisfying terminal outcome"
                )
            }
            Self::ObligationStateSubjectMismatchChirho(mint_identity_digest_chirho) => {
                return write!(
                    formatter_chirho,
                    "GD7 processing row under {mint_identity_digest_chirho} describes a different obligation"
                )
            }
            // Name the conservation LAW that fired, without rendering the amounts: an operator
            // needs to know which equation broke, and the quantities stay in the typed payload for
            // the caller that actually handles the incident.
            Self::ConservationIncidentChirho(incident_kind_chirho) => {
                return write!(
                    formatter_chirho,
                    "GD7 conservation snapshot failed the {} law",
                    conservation_law_name_chirho(incident_kind_chirho)
                )
            }
            _ => {}
        }
        formatter_chirho.write_str(match self {
            Self::TenantMigrationSourceFenceActiveChirho => {
                "tenant migration source fence blocks GD7 plan mutation"
            }
            Self::ConservationSnapshotUnavailableChirho => {
                "GD7 conservation snapshot is unavailable"
            }
            Self::InvalidConservationSnapshotSignatureChirho => {
                "GD7 conservation snapshot signature is invalid"
            }
            // Rendered above with its law named; this arm is unreachable prose only.
            Self::ConservationIncidentChirho(_) => "GD7 conservation snapshot failed a CF4 law",
            Self::InvalidReferenceChirho => "GD7 plan reference is invalid",
            Self::NoActiveReconciliationChirho => "GD7 reconciliation has no active checkpoint",
            Self::StaleCheckpointChirho => "GD7 plan driver checkpoint is stale",
            Self::InvalidPhaseChirho => "GD7 reconciliation phase cannot reduce a plan page",
            Self::NoUnreducedManifestPageChirho => "GD7 plan has no unreduced manifest page",
            Self::InvalidPageShapeChirho => "GD7 plan page shape is invalid",
            Self::MalformedPlanPageChirho => "GD7 plan page is malformed",
            Self::NonCanonicalPlanPageChirho => "GD7 plan page is not canonical",
            Self::OversizedPlanPageChirho => "GD7 plan page exceeds its fixed bound",
            Self::MalformedTerminalMarkerChirho => "GD7 terminal marker is malformed",
            Self::NonCanonicalTerminalMarkerChirho => "GD7 terminal marker is not canonical",
            Self::OversizedTerminalMarkerChirho => "GD7 terminal marker exceeds its fixed bound",
            Self::InvalidTerminalMarkerSignatureChirho => {
                "GD7 terminal marker signature is invalid"
            }
            Self::MissingTerminalMarkerChirho => "GD7 terminal marker is missing",
            Self::InvalidLosingRecordEncodingChirho => {
                "GD7 losing manifest record cannot be encoded canonically"
            }
            Self::InvalidLosingRecordSignatureChirho => {
                "GD7 losing manifest record signature is invalid"
            }
            Self::MissingObjectChirho => "GD7 plan object is missing",
            Self::ObjectDigestMismatchChirho => "GD7 plan object digest mismatches its address",
            Self::ImmutableCollisionChirho => "GD7 plan immutable object collided",
            Self::ArithmeticOverflowChirho => "GD7 plan counter overflowed",
            Self::MissingIntentEvidenceChirho => "GD7 plan intent evidence is missing",
            Self::IntentEvidenceUnavailableChirho => "GD7 plan intent evidence is unavailable",
            Self::InvalidIntentEvidenceChirho => "GD7 plan intent evidence is invalid",
            Self::IntentEvidenceMismatchChirho => {
                "GD7 plan intent evidence does not match the fact"
            }
            Self::MissingTerminalEvidenceChirho => "GD7 plan terminal evidence is missing",
            Self::TerminalEvidenceUnavailableChirho => "GD7 plan terminal evidence is unavailable",
            Self::InvalidTerminalEvidenceChirho => "GD7 plan terminal evidence is invalid",
            Self::OperatorRosterRefusalChirho(_) => "GD7 operator roster authorization refused",
            Self::TerminalEvidenceMismatchChirho => {
                "GD7 plan terminal evidence does not match the fact"
            }
            Self::EffectLineageMismatchChirho => "GD7 plan effect lineage does not match",
            Self::TerminalMarkerMismatchChirho => "GD7 plan terminal marker does not match",
            Self::ObligationNotInSealedPlanChirho => {
                "GD7 losing-effect obligation is not in the exact sealed plan"
            }
            // Located above with their coordinate; these are the un-located fallbacks, so removing
            // the early return degrades the message rather than panicking.
            Self::CumulativeDivergenceAtPlanPageChirho(_) => {
                "GD7 plan page cumulative count diverged"
            }
            Self::UnconvergedObligationChirho(_) => {
                "GD7 obligation has no satisfying terminal outcome"
            }
            Self::ObligationStateSubjectMismatchChirho(_) => {
                "GD7 processing row describes a different obligation"
            }
            Self::RecordFactChirho(_) => "GD7 plan record fact is invalid",
            Self::ManifestChirho(_) => "GD7 manifest evidence cannot be reduced",
            Self::StoreChirho(_) => "GD7 reconciliation checkpoint operation failed",
            Self::SerializationChirho => "GD7 plan serialization failed",
            Self::SigningChirho => "GD7 terminal marker signing failed",
            Self::StorageChirho => "GD7 plan storage operation failed",
        })
    }
}

impl Error for Gd7PlanRefusalChirho {}

impl From<EffectRecordFactRefusalChirho> for Gd7PlanRefusalChirho {
    fn from(error_chirho: EffectRecordFactRefusalChirho) -> Self {
        Self::RecordFactChirho(error_chirho)
    }
}

impl From<Gd7ManifestRefusalChirho> for Gd7PlanRefusalChirho {
    fn from(error_chirho: Gd7ManifestRefusalChirho) -> Self {
        Self::ManifestChirho(error_chirho)
    }
}

impl From<Gd7ReconciliationStoreRefusalChirho> for Gd7PlanRefusalChirho {
    fn from(error_chirho: Gd7ReconciliationStoreRefusalChirho) -> Self {
        Self::StoreChirho(error_chirho)
    }
}
