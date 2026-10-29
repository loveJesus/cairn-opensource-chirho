// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Actor-owned commit and restart verification for one exact GD7 adoption selector.
//!
//! The fixed reconciliation head is the sole mutable commit point. Its adoption binding proves
//! which sealed checkpoint was active at commit; it does not infer uniqueness from today's sealed
//! producer census. Restart point-loads that exact prior checkpoint and every immutable Cut A
//! input, then independently reopens and folds the selected journal before reporting adoption.
//! The group head remains present, so this selector grants no write authority and moves no served
//! or application ref.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

use super::adoption_chirho::{
    adoption_materialization_inputs_chirho, candidate_journal_path_chirho,
    candidate_projection_path_chirho, digest_bytes_chirho, inputs_path_chirho,
    Gd7AdoptionMaterializationInputsChirho, ReadOnlyWinnerJournalVerifierChirho,
};
use super::{ResidentGd7HeldPreparedAdoptionChirho, ResidentGd7HeldSealedPlanSnapshotChirho};
use crate::reconciliation_chirho::{
    gd7_held_evidence_transfer_identity_digest_chirho, gd7_reconciliation_identity_digest_chirho,
    load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho, ActiveGd7ReconciliationChirho,
    Gd7AccountNetCompositionRefusalChirho, Gd7AdoptionCheckpointBindingChirho,
    Gd7HeldEvidenceTransferIdentityChirho, Gd7HeldEvidenceTransferPhaseChirho,
    Gd7HeldEvidenceTransferStoreChirho, Gd7HeldEvidenceTransferStoreRefusalChirho,
    Gd7LedgerRecordVerifierPortChirho, Gd7ReadOnlyBranchRefusalChirho,
    Gd7ReconciliationIdentityChirho, Gd7ReconciliationPhaseChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationStoreChirho,
    Gd7ReconciliationStoreRefusalChirho, Gd7ReconciliationVerifierPortChirho,
    GD7_ADOPTION_CHECKPOINT_BINDING_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerifierViewChirho, KindRegistryViewChirho, MembershipViewChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_log_chirho::ports_chirho::{LedgerClockPortChirho, LedgerStoragePortChirho};
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use cairn_ledger_read_model_chirho::feeder_chirho::{
    ProjectionFoldPortChirho, VerifiedSourceStateChirho,
};
use cairn_ledger_read_model_chirho::AccountNetProjectionFoldChirho;
use std::error::Error;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidentGd7HeldAdoptedSnapshotChirho {
    checkpoint_ref_chirho: String,
    plan_checkpoint_ref_chirho: String,
    input_binding_digest_chirho: String,
    candidate_journal_digest_chirho: String,
    candidate_record_count_chirho: u64,
    candidate_projection_digest_chirho: String,
    candidate_projection_row_count_chirho: u64,
}

impl ResidentGd7HeldAdoptedSnapshotChirho {
    pub fn checkpoint_ref_chirho(&self) -> &str {
        &self.checkpoint_ref_chirho
    }

    pub fn plan_checkpoint_ref_chirho(&self) -> &str {
        &self.plan_checkpoint_ref_chirho
    }

    pub fn input_binding_digest_chirho(&self) -> &str {
        &self.input_binding_digest_chirho
    }

    pub fn candidate_journal_digest_chirho(&self) -> &str {
        &self.candidate_journal_digest_chirho
    }

    pub fn candidate_record_count_chirho(&self) -> u64 {
        self.candidate_record_count_chirho
    }

    pub fn candidate_projection_digest_chirho(&self) -> &str {
        &self.candidate_projection_digest_chirho
    }

    pub fn candidate_projection_row_count_chirho(&self) -> u64 {
        self.candidate_projection_row_count_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum ResidentGd7HeldAdoptionCommitOutcomeChirho {
    CommittedChirho(ResidentGd7HeldAdoptedSnapshotChirho),
    AlreadyAdoptedExactChirho(ResidentGd7HeldAdoptedSnapshotChirho),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum ResidentGd7HeldAdoptionCommitRefusalChirho {
    ActiveCheckpointChangedChirho,
    ActiveEvidenceChangedChirho,
    ActiveReadOnlyBranchChangedChirho,
    InvalidAdoptionBindingChirho,
    PriorCheckpointMismatchChirho,
    AlreadyAdoptedDifferentCandidateChirho,
    MissingCandidateObjectChirho,
    CandidateDigestMismatchChirho,
    CandidateJournalMismatchChirho,
    CandidateProjectionMismatchChirho,
    ReconciliationStoreChirho(Gd7ReconciliationStoreRefusalChirho),
    EvidenceStoreChirho(Gd7HeldEvidenceTransferStoreRefusalChirho),
    ReadOnlyBranchChirho(Gd7ReadOnlyBranchRefusalChirho),
    AccountNetChirho(Gd7AccountNetCompositionRefusalChirho),
    SerializationChirho,
    StorageChirho,
}

impl fmt::Display for ResidentGd7HeldAdoptionCommitRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActiveCheckpointChangedChirho => {
                formatter_chirho.write_str("GD7 adoption active checkpoint changed")
            }
            Self::ActiveEvidenceChangedChirho => {
                formatter_chirho.write_str("GD7 adoption active evidence checkpoint changed")
            }
            Self::ActiveReadOnlyBranchChangedChirho => {
                formatter_chirho.write_str("GD7 adoption active read-only branch changed")
            }
            Self::InvalidAdoptionBindingChirho => {
                formatter_chirho.write_str("GD7 adoption checkpoint binding is invalid")
            }
            Self::PriorCheckpointMismatchChirho => formatter_chirho
                .write_str("GD7 adoption prior PlanSealed checkpoint does not match"),
            Self::AlreadyAdoptedDifferentCandidateChirho => formatter_chirho
                .write_str("GD7 adoption is already committed for a different candidate pair"),
            Self::MissingCandidateObjectChirho => {
                formatter_chirho.write_str("GD7 adoption candidate object is missing")
            }
            Self::CandidateDigestMismatchChirho => {
                formatter_chirho.write_str("GD7 adoption candidate digest or length differs")
            }
            Self::CandidateJournalMismatchChirho => {
                formatter_chirho.write_str("GD7 adoption candidate journal does not reverify")
            }
            Self::CandidateProjectionMismatchChirho => formatter_chirho
                .write_str("GD7 adoption candidate projection differs from accepted evidence"),
            Self::ReconciliationStoreChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 reconciliation store refused: {error_chirho}"
                )
            }
            Self::EvidenceStoreChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 evidence store refused: {error_chirho}"
                )
            }
            Self::ReadOnlyBranchChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 read-only branch refused: {error_chirho}"
                )
            }
            Self::AccountNetChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 account-net evidence refused: {error_chirho}"
                )
            }
            Self::SerializationChirho => {
                formatter_chirho.write_str("GD7 adoption binding serialization failed")
            }
            Self::StorageChirho => {
                formatter_chirho.write_str("GD7 adoption candidate storage failed")
            }
        }
    }
}

impl Error for ResidentGd7HeldAdoptionCommitRefusalChirho {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ReconciliationStoreChirho(error_chirho) => Some(error_chirho),
            Self::EvidenceStoreChirho(error_chirho) => Some(error_chirho),
            Self::ReadOnlyBranchChirho(error_chirho) => Some(error_chirho),
            Self::AccountNetChirho(error_chirho) => Some(error_chirho),
            _ => None,
        }
    }
}

impl From<Gd7ReconciliationStoreRefusalChirho> for ResidentGd7HeldAdoptionCommitRefusalChirho {
    fn from(error_chirho: Gd7ReconciliationStoreRefusalChirho) -> Self {
        Self::ReconciliationStoreChirho(error_chirho)
    }
}

impl From<Gd7HeldEvidenceTransferStoreRefusalChirho>
    for ResidentGd7HeldAdoptionCommitRefusalChirho
{
    fn from(error_chirho: Gd7HeldEvidenceTransferStoreRefusalChirho) -> Self {
        Self::EvidenceStoreChirho(error_chirho)
    }
}

impl From<Gd7ReadOnlyBranchRefusalChirho> for ResidentGd7HeldAdoptionCommitRefusalChirho {
    fn from(error_chirho: Gd7ReadOnlyBranchRefusalChirho) -> Self {
        Self::ReadOnlyBranchChirho(error_chirho)
    }
}

impl From<Gd7AccountNetCompositionRefusalChirho> for ResidentGd7HeldAdoptionCommitRefusalChirho {
    fn from(error_chirho: Gd7AccountNetCompositionRefusalChirho) -> Self {
        Self::AccountNetChirho(error_chirho)
    }
}

pub(crate) struct Gd7HeldAdoptionCommitPortsChirho<'ports_chirho> {
    pub authority_storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    pub candidate_storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    pub held_signer_chirho: &'ports_chirho dyn Gd7ReconciliationSignerPortChirho,
    pub winner_control_verifier_chirho: &'ports_chirho dyn Gd7ReconciliationVerifierPortChirho,
    pub winner_ledger_verifier_chirho: &'ports_chirho dyn Gd7LedgerRecordVerifierPortChirho,
    pub clock_chirho: &'ports_chirho dyn LedgerClockPortChirho,
    pub membership_chirho: &'ports_chirho dyn MembershipViewChirho,
    pub kind_registry_chirho: &'ports_chirho dyn KindRegistryViewChirho,
    pub authority_chirho: &'ports_chirho dyn AuthorityVerifierViewChirho,
    pub cluster_id_chirho: &'ports_chirho ClusterIdChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CandidateMeasurementsChirho {
    journal_digest_chirho: String,
    journal_byte_len_chirho: u64,
    record_count_chirho: u64,
    projection_digest_chirho: String,
    projection_byte_len_chirho: u64,
    projection_row_count_chirho: u64,
}

pub(crate) fn commit_or_reload_gd7_held_adoption_chirho(
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    winner_fork_witness_object_digest_chirho: &str,
    prepared_chirho: &ResidentGd7HeldPreparedAdoptionChirho,
    ports_chirho: &Gd7HeldAdoptionCommitPortsChirho<'_>,
) -> Result<ResidentGd7HeldAdoptionCommitOutcomeChirho, ResidentGd7HeldAdoptionCommitRefusalChirho>
{
    let store_chirho = Gd7ReconciliationStoreChirho::new_authenticated_chirho(
        ports_chirho.authority_storage_chirho,
        ports_chirho.held_signer_chirho,
        identity_chirho.clone(),
        winner_fork_witness_object_digest_chirho.to_owned(),
    )?;
    let active_chirho = store_chirho
        .load_active_chirho()?
        .ok_or(ResidentGd7HeldAdoptionCommitRefusalChirho::ActiveCheckpointChangedChirho)?;
    match active_chirho.checkpoint_chirho.state_chirho.phase_chirho {
        Gd7ReconciliationPhaseChirho::PlanSealedChirho => {
            if active_chirho.checkpoint_ref_chirho != prepared_chirho.plan_checkpoint_ref_chirho() {
                return Err(
                    ResidentGd7HeldAdoptionCommitRefusalChirho::ActiveCheckpointChangedChirho,
                );
            }
            let binding_chirho = verify_candidate_for_plan_chirho(
                &active_chirho.checkpoint_ref_chirho,
                &active_chirho.checkpoint_chirho,
                prepared_chirho.input_binding_digest_chirho(),
                CandidateMeasurementsChirho::from_prepared_chirho(prepared_chirho),
                Some(prepared_chirho),
                ports_chirho,
            )?;
            store_chirho.commit_adopted_held_checkpoint_chirho(
                &active_chirho.checkpoint_ref_chirho,
                binding_chirho,
            )?;
            let snapshot_chirho = verify_active_gd7_held_adoption_chirho(
                identity_chirho,
                winner_fork_witness_object_digest_chirho,
                ports_chirho,
            )?;
            Ok(ResidentGd7HeldAdoptionCommitOutcomeChirho::CommittedChirho(
                snapshot_chirho,
            ))
        }
        Gd7ReconciliationPhaseChirho::AdoptedHeldChirho => {
            let snapshot_chirho = verify_active_gd7_held_adoption_chirho(
                identity_chirho,
                winner_fork_witness_object_digest_chirho,
                ports_chirho,
            )?;
            if snapshot_matches_prepared_chirho(&snapshot_chirho, prepared_chirho) {
                Ok(
                    ResidentGd7HeldAdoptionCommitOutcomeChirho::AlreadyAdoptedExactChirho(
                        snapshot_chirho,
                    ),
                )
            } else {
                Err(
                    ResidentGd7HeldAdoptionCommitRefusalChirho::AlreadyAdoptedDifferentCandidateChirho,
                )
            }
        }
        _ => Err(ResidentGd7HeldAdoptionCommitRefusalChirho::ActiveCheckpointChangedChirho),
    }
}

pub(crate) fn verify_active_gd7_held_adoption_chirho(
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    winner_fork_witness_object_digest_chirho: &str,
    ports_chirho: &Gd7HeldAdoptionCommitPortsChirho<'_>,
) -> Result<ResidentGd7HeldAdoptedSnapshotChirho, ResidentGd7HeldAdoptionCommitRefusalChirho> {
    let store_chirho = Gd7ReconciliationStoreChirho::new_authenticated_chirho(
        ports_chirho.authority_storage_chirho,
        ports_chirho.held_signer_chirho,
        identity_chirho.clone(),
        winner_fork_witness_object_digest_chirho.to_owned(),
    )?;
    let active_chirho = store_chirho
        .load_active_chirho()?
        .ok_or(ResidentGd7HeldAdoptionCommitRefusalChirho::ActiveCheckpointChangedChirho)?;
    let binding_chirho = active_chirho
        .checkpoint_chirho
        .state_chirho
        .adoption_binding_chirho
        .as_ref()
        .ok_or(ResidentGd7HeldAdoptionCommitRefusalChirho::InvalidAdoptionBindingChirho)?;
    if active_chirho.checkpoint_chirho.state_chirho.phase_chirho
        != Gd7ReconciliationPhaseChirho::AdoptedHeldChirho
        || active_chirho
            .checkpoint_chirho
            .state_chirho
            .previous_checkpoint_ref_chirho
            .as_deref()
            != Some(binding_chirho.plan_checkpoint_ref_chirho.as_str())
    {
        return Err(ResidentGd7HeldAdoptionCommitRefusalChirho::InvalidAdoptionBindingChirho);
    }
    let plan_checkpoint_chirho = load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho(
        ports_chirho.authority_storage_chirho,
        ports_chirho.held_signer_chirho,
        &binding_chirho.plan_checkpoint_ref_chirho,
    )?;
    require_exact_plan_link_chirho(&active_chirho, &plan_checkpoint_chirho)?;
    let verified_binding_chirho = verify_candidate_for_plan_chirho(
        &binding_chirho.plan_checkpoint_ref_chirho,
        &plan_checkpoint_chirho,
        &binding_chirho.materialization_input_binding_digest_chirho,
        CandidateMeasurementsChirho::from_binding_chirho(binding_chirho),
        None,
        ports_chirho,
    )?;
    if &verified_binding_chirho != binding_chirho {
        return Err(ResidentGd7HeldAdoptionCommitRefusalChirho::InvalidAdoptionBindingChirho);
    }
    if store_chirho.load_active_chirho()?.as_ref() != Some(&active_chirho) {
        return Err(ResidentGd7HeldAdoptionCommitRefusalChirho::ActiveCheckpointChangedChirho);
    }
    Ok(snapshot_from_active_chirho(&active_chirho, binding_chirho))
}

fn verify_candidate_for_plan_chirho(
    plan_checkpoint_ref_chirho: &str,
    plan_checkpoint_chirho: &crate::reconciliation_chirho::Gd7ReconciliationCheckpointChirho,
    input_binding_digest_chirho: &str,
    measurements_chirho: CandidateMeasurementsChirho,
    prepared_chirho: Option<&ResidentGd7HeldPreparedAdoptionChirho>,
    ports_chirho: &Gd7HeldAdoptionCommitPortsChirho<'_>,
) -> Result<Gd7AdoptionCheckpointBindingChirho, ResidentGd7HeldAdoptionCommitRefusalChirho> {
    if plan_checkpoint_chirho.state_chirho.phase_chirho
        != Gd7ReconciliationPhaseChirho::PlanSealedChirho
    {
        return Err(ResidentGd7HeldAdoptionCommitRefusalChirho::PriorCheckpointMismatchChirho);
    }
    let input_path_chirho = inputs_path_chirho(input_binding_digest_chirho);
    let input_bytes_chirho =
        read_required_chirho(ports_chirho.candidate_storage_chirho, &input_path_chirho)?;
    if digest_bytes_chirho(&input_bytes_chirho) != input_binding_digest_chirho {
        return Err(ResidentGd7HeldAdoptionCommitRefusalChirho::CandidateDigestMismatchChirho);
    }
    let inputs_chirho: Gd7AdoptionMaterializationInputsChirho =
        serde_json::from_slice(&input_bytes_chirho)
            .map_err(|_| ResidentGd7HeldAdoptionCommitRefusalChirho::SerializationChirho)?;
    if serde_json::to_vec(&inputs_chirho)
        .map_err(|_| ResidentGd7HeldAdoptionCommitRefusalChirho::SerializationChirho)?
        != input_bytes_chirho
        || inputs_chirho.plan_checkpoint_ref_chirho != plan_checkpoint_ref_chirho
    {
        return Err(ResidentGd7HeldAdoptionCommitRefusalChirho::InvalidAdoptionBindingChirho);
    }

    let transfer_identity_chirho = Gd7HeldEvidenceTransferIdentityChirho {
        reconciliation_identity_chirho: plan_checkpoint_chirho.identity_chirho.clone(),
        reconciliation_checkpoint_ref_chirho: plan_checkpoint_ref_chirho.to_owned(),
        held_view_transfer_checkpoint_ref_chirho: inputs_chirho
            .held_view_checkpoint_ref_chirho
            .clone(),
        winner_handoff_attempt_digest_chirho: inputs_chirho
            .winner_handoff_attempt_digest_chirho
            .clone(),
    };
    let evidence_store_chirho = Gd7HeldEvidenceTransferStoreChirho::new_chirho(
        ports_chirho.authority_storage_chirho,
        ports_chirho.held_signer_chirho,
        ports_chirho.winner_control_verifier_chirho,
        ports_chirho.winner_ledger_verifier_chirho,
        transfer_identity_chirho,
    )?;
    if prepared_chirho.is_some()
        && evidence_store_chirho
            .load_active_chirho()?
            .as_ref()
            .map(|active_chirho| active_chirho.checkpoint_ref_chirho.as_str())
            != Some(inputs_chirho.evidence_checkpoint_ref_chirho.as_str())
    {
        return Err(ResidentGd7HeldAdoptionCommitRefusalChirho::ActiveEvidenceChangedChirho);
    }
    let evidence_checkpoint_chirho = evidence_store_chirho
        .load_checkpoint_by_ref_chirho(&inputs_chirho.evidence_checkpoint_ref_chirho)?;
    if evidence_checkpoint_chirho.checkpoint_chirho.phase_chirho
        != Gd7HeldEvidenceTransferPhaseChirho::CompleteChirho
    {
        return Err(ResidentGd7HeldAdoptionCommitRefusalChirho::InvalidAdoptionBindingChirho);
    }
    let composition_chirho = evidence_store_chirho
        .verify_account_net_composition_at_checkpoint_chirho(
            &inputs_chirho.evidence_checkpoint_ref_chirho,
        )?;
    let branch_checkpoint_chirho = evidence_store_chirho
        .verify_read_only_branch_checkpoint_at_ref_chirho(
            &inputs_chirho.read_only_branch_checkpoint_ref_chirho,
        )?;
    if prepared_chirho.is_some()
        && evidence_store_chirho
            .load_active_read_only_branch_evidence_chirho()?
            .as_ref()
            .map(|active_chirho| active_chirho.checkpoint_ref_chirho.as_str())
            != Some(
                inputs_chirho
                    .read_only_branch_checkpoint_ref_chirho
                    .as_str(),
            )
    {
        return Err(ResidentGd7HeldAdoptionCommitRefusalChirho::ActiveReadOnlyBranchChangedChirho);
    }
    let sealed_plan_chirho =
        sealed_plan_snapshot_chirho(plan_checkpoint_ref_chirho, plan_checkpoint_chirho)?;
    let expected_transfer_identity_digest_chirho =
        gd7_held_evidence_transfer_identity_digest_chirho(
            &branch_checkpoint_chirho
                .checkpoint_chirho
                .transfer_identity_chirho,
        )
        .map_err(|_| ResidentGd7HeldAdoptionCommitRefusalChirho::InvalidAdoptionBindingChirho)?;
    let expected_inputs_chirho = adoption_materialization_inputs_chirho(
        &sealed_plan_chirho,
        expected_transfer_identity_digest_chirho,
        &evidence_checkpoint_chirho,
        &branch_checkpoint_chirho,
        &composition_chirho,
    );
    if inputs_chirho != expected_inputs_chirho {
        return Err(ResidentGd7HeldAdoptionCommitRefusalChirho::InvalidAdoptionBindingChirho);
    }
    require_candidate_measurements_chirho(
        &inputs_chirho,
        &measurements_chirho,
        prepared_chirho,
        ports_chirho,
        &plan_checkpoint_chirho.identity_chirho,
        composition_chirho.canonical_projection_bytes_chirho(),
    )?;
    binding_from_verified_inputs_chirho(inputs_chirho, measurements_chirho)
}

fn require_candidate_measurements_chirho(
    inputs_chirho: &Gd7AdoptionMaterializationInputsChirho,
    measurements_chirho: &CandidateMeasurementsChirho,
    prepared_chirho: Option<&ResidentGd7HeldPreparedAdoptionChirho>,
    ports_chirho: &Gd7HeldAdoptionCommitPortsChirho<'_>,
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    accepted_projection_bytes_chirho: &[u8],
) -> Result<(), ResidentGd7HeldAdoptionCommitRefusalChirho> {
    if measurements_chirho.record_count_chirho != inputs_chirho.canonical_record_count_chirho
        || measurements_chirho.projection_row_count_chirho
            != inputs_chirho.account_net_row_count_chirho
    {
        return Err(ResidentGd7HeldAdoptionCommitRefusalChirho::InvalidAdoptionBindingChirho);
    }
    let input_binding_digest_chirho = digest_bytes_chirho(
        &serde_json::to_vec(inputs_chirho)
            .map_err(|_| ResidentGd7HeldAdoptionCommitRefusalChirho::SerializationChirho)?,
    );
    let journal_path_chirho = candidate_journal_path_chirho(&input_binding_digest_chirho);
    let projection_path_chirho = candidate_projection_path_chirho(&input_binding_digest_chirho);
    if let Some(prepared_chirho) = prepared_chirho {
        if prepared_chirho.candidate_journal_path_chirho() != &journal_path_chirho
            || prepared_chirho.candidate_projection_path_chirho() != &projection_path_chirho
        {
            return Err(ResidentGd7HeldAdoptionCommitRefusalChirho::InvalidAdoptionBindingChirho);
        }
    }
    let journal_bytes_chirho =
        read_required_chirho(ports_chirho.candidate_storage_chirho, &journal_path_chirho)?;
    let projection_bytes_chirho = read_required_chirho(
        ports_chirho.candidate_storage_chirho,
        &projection_path_chirho,
    )?;
    if u64::try_from(journal_bytes_chirho.len()).ok()
        != Some(measurements_chirho.journal_byte_len_chirho)
        || digest_bytes_chirho(&journal_bytes_chirho) != measurements_chirho.journal_digest_chirho
        || u64::try_from(projection_bytes_chirho.len()).ok()
            != Some(measurements_chirho.projection_byte_len_chirho)
        || digest_bytes_chirho(&projection_bytes_chirho)
            != measurements_chirho.projection_digest_chirho
    {
        return Err(ResidentGd7HeldAdoptionCommitRefusalChirho::CandidateDigestMismatchChirho);
    }
    if projection_bytes_chirho != accepted_projection_bytes_chirho
        || digest_bytes_chirho(accepted_projection_bytes_chirho)
            != inputs_chirho.accepted_projection_digest_chirho
    {
        return Err(ResidentGd7HeldAdoptionCommitRefusalChirho::CandidateProjectionMismatchChirho);
    }
    let verifier_chirho = ReadOnlyWinnerJournalVerifierChirho {
        verifier_chirho: ports_chirho.winner_ledger_verifier_chirho,
    };
    let journal_chirho = LedgerJournalChirho::open_read_only_full_chirho(
        JournalPortsChirho {
            storage_chirho: ports_chirho.candidate_storage_chirho,
            signer_chirho: &verifier_chirho,
            clock_chirho: ports_chirho.clock_chirho,
            membership_chirho: ports_chirho.membership_chirho,
            kind_registry_chirho: ports_chirho.kind_registry_chirho,
            authority_chirho: ports_chirho.authority_chirho,
        },
        journal_path_chirho,
        ports_chirho.cluster_id_chirho,
    )
    .map_err(|_| ResidentGd7HeldAdoptionCommitRefusalChirho::CandidateJournalMismatchChirho)?;
    let source_cut_chirho = journal_chirho.effect_intent_cut_chirho();
    if journal_chirho.tail_seq_chirho() != measurements_chirho.record_count_chirho
        || source_cut_chirho.journal_genesis_digest_chirho.0
            != identity_chirho.winner_journal_genesis_digest_chirho
        || source_cut_chirho.tail_record_digest_chirho.0
            != identity_chirho
                .winner_journal_tail_chirho
                .record_digest_chirho
    {
        return Err(ResidentGd7HeldAdoptionCommitRefusalChirho::CandidateJournalMismatchChirho);
    }
    let folded_projection_chirho = AccountNetProjectionFoldChirho
        .fold_chirho(&VerifiedSourceStateChirho {
            journal_chirho: &journal_chirho,
        })
        .map_err(|_| {
            ResidentGd7HeldAdoptionCommitRefusalChirho::CandidateProjectionMismatchChirho
        })?;
    if folded_projection_chirho != projection_bytes_chirho {
        return Err(ResidentGd7HeldAdoptionCommitRefusalChirho::CandidateProjectionMismatchChirho);
    }
    Ok(())
}

fn require_exact_plan_link_chirho(
    active_chirho: &ActiveGd7ReconciliationChirho,
    plan_checkpoint_chirho: &crate::reconciliation_chirho::Gd7ReconciliationCheckpointChirho,
) -> Result<(), ResidentGd7HeldAdoptionCommitRefusalChirho> {
    let active_checkpoint_chirho = &active_chirho.checkpoint_chirho;
    let active_state_chirho = &active_checkpoint_chirho.state_chirho;
    let plan_state_chirho = &plan_checkpoint_chirho.state_chirho;
    if plan_state_chirho.phase_chirho != Gd7ReconciliationPhaseChirho::PlanSealedChirho
        || active_checkpoint_chirho.identity_chirho != plan_checkpoint_chirho.identity_chirho
        || active_checkpoint_chirho.winner_fork_witness_object_digest_chirho
            != plan_checkpoint_chirho.winner_fork_witness_object_digest_chirho
        || plan_state_chirho.transition_seq_chirho.checked_add(1)
            != Some(active_state_chirho.transition_seq_chirho)
        || active_state_chirho.manifest_head_ref_chirho
            != plan_state_chirho.manifest_head_ref_chirho
        || active_state_chirho.manifest_page_count_chirho
            != plan_state_chirho.manifest_page_count_chirho
        || active_state_chirho.manifest_record_count_chirho
            != plan_state_chirho.manifest_record_count_chirho
        || active_state_chirho.plan_head_ref_chirho != plan_state_chirho.plan_head_ref_chirho
        || active_state_chirho.plan_page_count_chirho != plan_state_chirho.plan_page_count_chirho
        || active_state_chirho.sealed_plan_ref_chirho != plan_state_chirho.sealed_plan_ref_chirho
        || active_state_chirho.effect_obligation_count_chirho
            != plan_state_chirho.effect_obligation_count_chirho
        || active_state_chirho.cursor_object_ref_chirho.is_some()
    {
        return Err(ResidentGd7HeldAdoptionCommitRefusalChirho::PriorCheckpointMismatchChirho);
    }
    Ok(())
}

fn sealed_plan_snapshot_chirho(
    checkpoint_ref_chirho: &str,
    checkpoint_chirho: &crate::reconciliation_chirho::Gd7ReconciliationCheckpointChirho,
) -> Result<ResidentGd7HeldSealedPlanSnapshotChirho, ResidentGd7HeldAdoptionCommitRefusalChirho> {
    let state_chirho = &checkpoint_chirho.state_chirho;
    Ok(ResidentGd7HeldSealedPlanSnapshotChirho {
        reconciliation_identity_digest_chirho: gd7_reconciliation_identity_digest_chirho(
            &checkpoint_chirho.identity_chirho,
        )?,
        checkpoint_ref_chirho: checkpoint_ref_chirho.to_owned(),
        sealed_plan_ref_chirho: state_chirho
            .sealed_plan_ref_chirho
            .clone()
            .ok_or(ResidentGd7HeldAdoptionCommitRefusalChirho::PriorCheckpointMismatchChirho)?,
        winner_fork_witness_object_digest_chirho: checkpoint_chirho
            .winner_fork_witness_object_digest_chirho
            .clone(),
        winner_term_chirho: checkpoint_chirho.identity_chirho.winner_term_chirho,
        plan_page_count_chirho: state_chirho.plan_page_count_chirho,
        manifest_record_count_chirho: state_chirho.manifest_record_count_chirho,
        effect_obligation_count_chirho: state_chirho.effect_obligation_count_chirho,
    })
}

fn binding_from_verified_inputs_chirho(
    inputs_chirho: Gd7AdoptionMaterializationInputsChirho,
    measurements_chirho: CandidateMeasurementsChirho,
) -> Result<Gd7AdoptionCheckpointBindingChirho, ResidentGd7HeldAdoptionCommitRefusalChirho> {
    let input_binding_digest_chirho = digest_bytes_chirho(
        &serde_json::to_vec(&inputs_chirho)
            .map_err(|_| ResidentGd7HeldAdoptionCommitRefusalChirho::SerializationChirho)?,
    );
    Ok(Gd7AdoptionCheckpointBindingChirho {
        schema_chirho: GD7_ADOPTION_CHECKPOINT_BINDING_SCHEMA_V1_CHIRHO.to_owned(),
        plan_checkpoint_ref_chirho: inputs_chirho.plan_checkpoint_ref_chirho,
        materialization_input_binding_digest_chirho: input_binding_digest_chirho,
        evidence_checkpoint_ref_chirho: inputs_chirho.evidence_checkpoint_ref_chirho,
        evidence_manifest_ref_chirho: inputs_chirho.evidence_manifest_ref_chirho,
        held_view_checkpoint_ref_chirho: inputs_chirho.held_view_checkpoint_ref_chirho,
        held_view_bundle_root_ref_chirho: inputs_chirho.held_view_bundle_root_ref_chirho,
        read_only_branch_checkpoint_ref_chirho: inputs_chirho
            .read_only_branch_checkpoint_ref_chirho,
        prefix_root_ref_chirho: inputs_chirho.prefix_root_ref_chirho,
        winner_history_root_ref_chirho: inputs_chirho.winner_history_root_ref_chirho,
        fork_baseline_root_ref_chirho: inputs_chirho.fork_baseline_root_ref_chirho,
        winner_handoff_attempt_digest_chirho: inputs_chirho.winner_handoff_attempt_digest_chirho,
        projection_fold_ref_chirho: inputs_chirho.projection_fold_ref_chirho,
        accepted_projection_digest_chirho: inputs_chirho.accepted_projection_digest_chirho,
        candidate_journal_digest_chirho: measurements_chirho.journal_digest_chirho,
        candidate_journal_byte_len_chirho: measurements_chirho.journal_byte_len_chirho,
        candidate_record_count_chirho: measurements_chirho.record_count_chirho,
        candidate_projection_digest_chirho: measurements_chirho.projection_digest_chirho,
        candidate_projection_byte_len_chirho: measurements_chirho.projection_byte_len_chirho,
        candidate_projection_row_count_chirho: measurements_chirho.projection_row_count_chirho,
    })
}

fn snapshot_from_active_chirho(
    active_chirho: &ActiveGd7ReconciliationChirho,
    binding_chirho: &Gd7AdoptionCheckpointBindingChirho,
) -> ResidentGd7HeldAdoptedSnapshotChirho {
    ResidentGd7HeldAdoptedSnapshotChirho {
        checkpoint_ref_chirho: active_chirho.checkpoint_ref_chirho.clone(),
        plan_checkpoint_ref_chirho: binding_chirho.plan_checkpoint_ref_chirho.clone(),
        input_binding_digest_chirho: binding_chirho
            .materialization_input_binding_digest_chirho
            .clone(),
        candidate_journal_digest_chirho: binding_chirho.candidate_journal_digest_chirho.clone(),
        candidate_record_count_chirho: binding_chirho.candidate_record_count_chirho,
        candidate_projection_digest_chirho: binding_chirho
            .candidate_projection_digest_chirho
            .clone(),
        candidate_projection_row_count_chirho: binding_chirho.candidate_projection_row_count_chirho,
    }
}

fn snapshot_matches_prepared_chirho(
    snapshot_chirho: &ResidentGd7HeldAdoptedSnapshotChirho,
    prepared_chirho: &ResidentGd7HeldPreparedAdoptionChirho,
) -> bool {
    snapshot_chirho.plan_checkpoint_ref_chirho == prepared_chirho.plan_checkpoint_ref_chirho()
        && snapshot_chirho.input_binding_digest_chirho
            == prepared_chirho.input_binding_digest_chirho()
        && snapshot_chirho.candidate_journal_digest_chirho
            == prepared_chirho.candidate_journal_digest_chirho()
        && snapshot_chirho.candidate_record_count_chirho
            == prepared_chirho.candidate_record_count_chirho()
        && snapshot_chirho.candidate_projection_digest_chirho
            == prepared_chirho.candidate_projection_digest_chirho()
        && snapshot_chirho.candidate_projection_row_count_chirho
            == prepared_chirho.candidate_projection_row_count_chirho()
}

impl CandidateMeasurementsChirho {
    fn from_prepared_chirho(prepared_chirho: &ResidentGd7HeldPreparedAdoptionChirho) -> Self {
        Self {
            journal_digest_chirho: prepared_chirho.candidate_journal_digest_chirho().to_owned(),
            journal_byte_len_chirho: prepared_chirho.candidate_journal_byte_len_chirho(),
            record_count_chirho: prepared_chirho.candidate_record_count_chirho(),
            projection_digest_chirho: prepared_chirho
                .candidate_projection_digest_chirho()
                .to_owned(),
            projection_byte_len_chirho: prepared_chirho.candidate_projection_byte_len_chirho(),
            projection_row_count_chirho: prepared_chirho.candidate_projection_row_count_chirho(),
        }
    }

    fn from_binding_chirho(binding_chirho: &Gd7AdoptionCheckpointBindingChirho) -> Self {
        Self {
            journal_digest_chirho: binding_chirho.candidate_journal_digest_chirho.clone(),
            journal_byte_len_chirho: binding_chirho.candidate_journal_byte_len_chirho,
            record_count_chirho: binding_chirho.candidate_record_count_chirho,
            projection_digest_chirho: binding_chirho.candidate_projection_digest_chirho.clone(),
            projection_byte_len_chirho: binding_chirho.candidate_projection_byte_len_chirho,
            projection_row_count_chirho: binding_chirho.candidate_projection_row_count_chirho,
        }
    }
}

fn read_required_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &cairn_ledger_log_chirho::ports_chirho::StoragePathChirho,
) -> Result<Vec<u8>, ResidentGd7HeldAdoptionCommitRefusalChirho> {
    storage_chirho
        .read_all_chirho(path_chirho)
        .map_err(|_| ResidentGd7HeldAdoptionCommitRefusalChirho::StorageChirho)?
        .ok_or(ResidentGd7HeldAdoptionCommitRefusalChirho::MissingCandidateObjectChirho)
}
