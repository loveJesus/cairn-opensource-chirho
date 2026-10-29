// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Actor-owned materialization of one checkpoint-pinned GD7 adoption candidate.
//!
//! This cut writes an ordinary journal object and its canonical account-net projection, then
//! returns an opaque prepared value. It does not change the reconciliation phase, publish an
//! adoption head, move a served ref, compensate, or grant writes. Evidence traversal is bounded by
//! its existing page limits. The deliberate `LedgerJournalChirho::open_read_only_full_chirho`
//! equivalence check performs one-time O(canonical-history) I/O and memory per new reconciliation;
//! a bounded full-open replacement is separate performance work. The golden three-record fixture
//! measures 3,460 canonical journal bytes; that measurement demonstrates cost, not a production
//! bound.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

use super::ResidentGd7HeldSealedPlanSnapshotChirho;
use crate::reconciliation_chirho::{
    gd7_held_evidence_transfer_identity_digest_chirho, gd7_reconciliation_identity_digest_chirho,
    Gd7AccountNetCompositionRefusalChirho, Gd7HeldEvidenceTransferPhaseChirho,
    Gd7HeldEvidenceTransferStoreChirho, Gd7HeldEvidenceTransferStoreRefusalChirho,
    Gd7LedgerRecordVerifierPortChirho, Gd7ReadOnlyBranchRefusalChirho,
};
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerifierViewChirho, KindRegistryViewChirho, MembershipViewChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerClockPortChirho, LedgerSignerPortChirho,
    LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use cairn_ledger_read_model_chirho::feeder_chirho::{
    ProjectionFoldPortChirho, VerifiedSourceStateChirho,
};
use cairn_ledger_read_model_chirho::{
    account_net_projection_fold_ref_chirho, AccountNetProjectionFoldChirho,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

pub(super) const GD7_ADOPTION_MATERIALIZATION_INPUTS_SCHEMA_V1_CHIRHO: &str =
    "gd7-adoption-materialization-inputs-v1-chirho";
const GD7_ADOPTION_MATERIALIZATION_NAMESPACE_CHIRHO: &str = "gd7-adoption-materialization-chirho";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidentGd7HeldPreparedAdoptionChirho {
    input_binding_digest_chirho: String,
    plan_checkpoint_ref_chirho: String,
    evidence_checkpoint_ref_chirho: String,
    read_only_branch_checkpoint_ref_chirho: String,
    candidate_journal_path_chirho: StoragePathChirho,
    candidate_journal_digest_chirho: String,
    candidate_journal_byte_len_chirho: u64,
    candidate_record_count_chirho: u64,
    candidate_projection_path_chirho: StoragePathChirho,
    candidate_projection_digest_chirho: String,
    candidate_projection_byte_len_chirho: u64,
    candidate_projection_row_count_chirho: u64,
}

impl ResidentGd7HeldPreparedAdoptionChirho {
    pub fn input_binding_digest_chirho(&self) -> &str {
        &self.input_binding_digest_chirho
    }

    pub fn plan_checkpoint_ref_chirho(&self) -> &str {
        &self.plan_checkpoint_ref_chirho
    }

    pub fn evidence_checkpoint_ref_chirho(&self) -> &str {
        &self.evidence_checkpoint_ref_chirho
    }

    pub fn read_only_branch_checkpoint_ref_chirho(&self) -> &str {
        &self.read_only_branch_checkpoint_ref_chirho
    }

    pub fn candidate_journal_path_chirho(&self) -> &StoragePathChirho {
        &self.candidate_journal_path_chirho
    }

    pub fn candidate_journal_digest_chirho(&self) -> &str {
        &self.candidate_journal_digest_chirho
    }

    pub fn candidate_journal_byte_len_chirho(&self) -> u64 {
        self.candidate_journal_byte_len_chirho
    }

    pub fn candidate_record_count_chirho(&self) -> u64 {
        self.candidate_record_count_chirho
    }

    pub fn candidate_projection_path_chirho(&self) -> &StoragePathChirho {
        &self.candidate_projection_path_chirho
    }

    pub fn candidate_projection_digest_chirho(&self) -> &str {
        &self.candidate_projection_digest_chirho
    }

    pub fn candidate_projection_byte_len_chirho(&self) -> u64 {
        self.candidate_projection_byte_len_chirho
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
pub enum ResidentGd7HeldAdoptionMaterializationRefusalChirho {
    IncompleteEvidenceChirho,
    StaleEvidenceChirho,
    InvalidInputBindingChirho,
    EvidenceStoreChirho(Gd7HeldEvidenceTransferStoreRefusalChirho),
    ReadOnlyBranchChirho(Gd7ReadOnlyBranchRefusalChirho),
    AccountNetChirho(Gd7AccountNetCompositionRefusalChirho),
    CanonicalHistoryChirho,
    JournalVerificationChirho,
    ProjectionFoldChirho,
    CurrentViewMismatchChirho,
    ImmutableCollisionChirho,
    StorageChirho,
    ArithmeticOverflowChirho,
}

impl fmt::Display for ResidentGd7HeldAdoptionMaterializationRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteEvidenceChirho => {
                formatter_chirho.write_str("GD7 adoption evidence is incomplete")
            }
            Self::StaleEvidenceChirho => {
                formatter_chirho.write_str("GD7 adoption evidence changed during materialization")
            }
            Self::InvalidInputBindingChirho => {
                formatter_chirho.write_str("GD7 adoption materialization inputs do not match")
            }
            Self::EvidenceStoreChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 held evidence store refused: {error_chirho}"
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
            Self::CanonicalHistoryChirho => {
                formatter_chirho.write_str("GD7 canonical history materialization failed")
            }
            Self::JournalVerificationChirho => {
                formatter_chirho.write_str("GD7 materialized journal verification failed")
            }
            Self::ProjectionFoldChirho => {
                formatter_chirho.write_str("GD7 materialized account-net fold failed")
            }
            Self::CurrentViewMismatchChirho => formatter_chirho
                .write_str("GD7 materialized account-net view differs from the accepted winner"),
            Self::ImmutableCollisionChirho => {
                formatter_chirho.write_str("GD7 adoption immutable object collided")
            }
            Self::StorageChirho => {
                formatter_chirho.write_str("GD7 adoption materialization storage failed")
            }
            Self::ArithmeticOverflowChirho => {
                formatter_chirho.write_str("GD7 adoption materialization arithmetic refused")
            }
        }
    }
}

impl Error for ResidentGd7HeldAdoptionMaterializationRefusalChirho {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::EvidenceStoreChirho(error_chirho) => Some(error_chirho),
            Self::ReadOnlyBranchChirho(error_chirho) => Some(error_chirho),
            Self::AccountNetChirho(error_chirho) => Some(error_chirho),
            _ => None,
        }
    }
}

impl From<Gd7HeldEvidenceTransferStoreRefusalChirho>
    for ResidentGd7HeldAdoptionMaterializationRefusalChirho
{
    fn from(error_chirho: Gd7HeldEvidenceTransferStoreRefusalChirho) -> Self {
        Self::EvidenceStoreChirho(error_chirho)
    }
}

impl From<Gd7ReadOnlyBranchRefusalChirho> for ResidentGd7HeldAdoptionMaterializationRefusalChirho {
    fn from(error_chirho: Gd7ReadOnlyBranchRefusalChirho) -> Self {
        Self::ReadOnlyBranchChirho(error_chirho)
    }
}

impl From<Gd7AccountNetCompositionRefusalChirho>
    for ResidentGd7HeldAdoptionMaterializationRefusalChirho
{
    fn from(error_chirho: Gd7AccountNetCompositionRefusalChirho) -> Self {
        Self::AccountNetChirho(error_chirho)
    }
}

pub(crate) struct Gd7HeldAdoptionMaterializationPortsChirho<'ports_chirho> {
    pub candidate_storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    pub winner_ledger_verifier_chirho: &'ports_chirho dyn Gd7LedgerRecordVerifierPortChirho,
    pub clock_chirho: &'ports_chirho dyn LedgerClockPortChirho,
    pub membership_chirho: &'ports_chirho dyn MembershipViewChirho,
    pub kind_registry_chirho: &'ports_chirho dyn KindRegistryViewChirho,
    pub authority_chirho: &'ports_chirho dyn AuthorityVerifierViewChirho,
    pub cluster_id_chirho: &'ports_chirho ClusterIdChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Gd7AdoptionMaterializationInputsChirho {
    pub(super) schema_chirho: String,
    pub(super) reconciliation_identity_digest_chirho: String,
    pub(super) transfer_identity_digest_chirho: String,
    pub(super) plan_checkpoint_ref_chirho: String,
    pub(super) sealed_plan_ref_chirho: String,
    pub(super) winner_fork_witness_object_digest_chirho: String,
    pub(super) plan_page_count_chirho: u64,
    pub(super) losing_manifest_record_count_chirho: u64,
    pub(super) effect_obligation_count_chirho: u64,
    pub(super) evidence_checkpoint_ref_chirho: String,
    pub(super) evidence_manifest_ref_chirho: String,
    pub(super) held_view_checkpoint_ref_chirho: String,
    pub(super) held_view_bundle_root_ref_chirho: String,
    pub(super) read_only_branch_checkpoint_ref_chirho: String,
    pub(super) prefix_root_ref_chirho: String,
    pub(super) winner_history_root_ref_chirho: String,
    pub(super) fork_baseline_root_ref_chirho: String,
    pub(super) winner_handoff_attempt_digest_chirho: String,
    pub(super) canonical_record_count_chirho: u64,
    pub(super) applied_winner_record_count_chirho: u64,
    pub(super) account_net_row_count_chirho: u64,
    pub(super) projection_fold_ref_chirho: String,
    pub(super) accepted_projection_digest_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Gd7AdoptionStagingJournalPathChirho(StoragePathChirho);

pub(super) fn adoption_materialization_inputs_chirho(
    sealed_plan_chirho: &ResidentGd7HeldSealedPlanSnapshotChirho,
    transfer_identity_digest_chirho: String,
    active_evidence_chirho: &crate::reconciliation_chirho::ActiveGd7HeldEvidenceTransferChirho,
    active_branch_chirho: &crate::reconciliation_chirho::ActiveGd7ReadOnlyBranchChirho,
    composition_chirho: &crate::reconciliation_chirho::VerifiedGd7AccountNetCompositionChirho,
) -> Gd7AdoptionMaterializationInputsChirho {
    let branch_checkpoint_chirho = &active_branch_chirho.checkpoint_chirho;
    let identity_chirho = &branch_checkpoint_chirho.transfer_identity_chirho;
    Gd7AdoptionMaterializationInputsChirho {
        schema_chirho: GD7_ADOPTION_MATERIALIZATION_INPUTS_SCHEMA_V1_CHIRHO.to_owned(),
        reconciliation_identity_digest_chirho: sealed_plan_chirho
            .reconciliation_identity_digest_chirho
            .clone(),
        transfer_identity_digest_chirho,
        plan_checkpoint_ref_chirho: sealed_plan_chirho.checkpoint_ref_chirho.clone(),
        sealed_plan_ref_chirho: sealed_plan_chirho.sealed_plan_ref_chirho.clone(),
        winner_fork_witness_object_digest_chirho: sealed_plan_chirho
            .winner_fork_witness_object_digest_chirho
            .clone(),
        plan_page_count_chirho: sealed_plan_chirho.plan_page_count_chirho,
        losing_manifest_record_count_chirho: sealed_plan_chirho.manifest_record_count_chirho,
        effect_obligation_count_chirho: sealed_plan_chirho.effect_obligation_count_chirho,
        evidence_checkpoint_ref_chirho: active_evidence_chirho.checkpoint_ref_chirho.clone(),
        evidence_manifest_ref_chirho: active_evidence_chirho
            .checkpoint_chirho
            .manifest_object_digest_chirho
            .clone(),
        held_view_checkpoint_ref_chirho: branch_checkpoint_chirho
            .held_view_checkpoint_ref_chirho
            .clone(),
        held_view_bundle_root_ref_chirho: branch_checkpoint_chirho
            .held_view_bundle_root_ref_chirho
            .clone(),
        read_only_branch_checkpoint_ref_chirho: active_branch_chirho.checkpoint_ref_chirho.clone(),
        prefix_root_ref_chirho: branch_checkpoint_chirho.prefix_root_ref_chirho.clone(),
        winner_history_root_ref_chirho: branch_checkpoint_chirho
            .winner_history_root_ref_chirho
            .clone(),
        fork_baseline_root_ref_chirho: branch_checkpoint_chirho
            .fork_baseline_root_ref_chirho
            .clone(),
        winner_handoff_attempt_digest_chirho: identity_chirho
            .winner_handoff_attempt_digest_chirho
            .clone(),
        canonical_record_count_chirho: branch_checkpoint_chirho.canonical_record_count_chirho,
        applied_winner_record_count_chirho: composition_chirho.applied_record_count_chirho(),
        account_net_row_count_chirho: composition_chirho.matched_row_count_chirho(),
        projection_fold_ref_chirho: account_net_projection_fold_ref_chirho().0,
        accepted_projection_digest_chirho: digest_bytes_chirho(
            composition_chirho.canonical_projection_bytes_chirho(),
        ),
    }
}

pub(super) struct ReadOnlyWinnerJournalVerifierChirho<'verifier_chirho> {
    pub(super) verifier_chirho: &'verifier_chirho dyn Gd7LedgerRecordVerifierPortChirho,
}

impl LedgerSignerPortChirho for ReadOnlyWinnerJournalVerifierChirho<'_> {
    fn sign_chirho(&self, _signed_content_line_chirho: &str) -> anyhow::Result<String> {
        anyhow::bail!("read-only winner journal verifier cannot sign")
    }

    fn key_id_chirho(&self) -> String {
        self.verifier_chirho.key_id_chirho()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.verifier_chirho
            .verify_chirho(signed_content_line_chirho, sig_chirho)
    }
}

pub(crate) fn materialize_gd7_held_adoption_candidate_chirho(
    evidence_store_chirho: &Gd7HeldEvidenceTransferStoreChirho<'_>,
    sealed_plan_chirho: &ResidentGd7HeldSealedPlanSnapshotChirho,
    expected_evidence_checkpoint_ref_chirho: &str,
    expected_branch_checkpoint_ref_chirho: &str,
    ports_chirho: Gd7HeldAdoptionMaterializationPortsChirho<'_>,
) -> Result<
    ResidentGd7HeldPreparedAdoptionChirho,
    ResidentGd7HeldAdoptionMaterializationRefusalChirho,
> {
    materialize_gd7_held_adoption_candidate_with_projection_chirho(
        evidence_store_chirho,
        sealed_plan_chirho,
        expected_evidence_checkpoint_ref_chirho,
        expected_branch_checkpoint_ref_chirho,
        ports_chirho,
        |projection_bytes_chirho| projection_bytes_chirho,
    )
}

#[cfg(test)]
pub(crate) fn materialize_gd7_held_adoption_candidate_with_projection_for_test_chirho(
    evidence_store_chirho: &Gd7HeldEvidenceTransferStoreChirho<'_>,
    sealed_plan_chirho: &ResidentGd7HeldSealedPlanSnapshotChirho,
    expected_evidence_checkpoint_ref_chirho: &str,
    expected_branch_checkpoint_ref_chirho: &str,
    ports_chirho: Gd7HeldAdoptionMaterializationPortsChirho<'_>,
    projection_transform_chirho: impl FnOnce(Vec<u8>) -> Vec<u8>,
) -> Result<
    ResidentGd7HeldPreparedAdoptionChirho,
    ResidentGd7HeldAdoptionMaterializationRefusalChirho,
> {
    materialize_gd7_held_adoption_candidate_with_projection_chirho(
        evidence_store_chirho,
        sealed_plan_chirho,
        expected_evidence_checkpoint_ref_chirho,
        expected_branch_checkpoint_ref_chirho,
        ports_chirho,
        projection_transform_chirho,
    )
}

fn materialize_gd7_held_adoption_candidate_with_projection_chirho(
    evidence_store_chirho: &Gd7HeldEvidenceTransferStoreChirho<'_>,
    sealed_plan_chirho: &ResidentGd7HeldSealedPlanSnapshotChirho,
    expected_evidence_checkpoint_ref_chirho: &str,
    expected_branch_checkpoint_ref_chirho: &str,
    ports_chirho: Gd7HeldAdoptionMaterializationPortsChirho<'_>,
    projection_transform_chirho: impl FnOnce(Vec<u8>) -> Vec<u8>,
) -> Result<
    ResidentGd7HeldPreparedAdoptionChirho,
    ResidentGd7HeldAdoptionMaterializationRefusalChirho,
> {
    let active_evidence_chirho = evidence_store_chirho
        .load_active_chirho()?
        .ok_or(ResidentGd7HeldAdoptionMaterializationRefusalChirho::IncompleteEvidenceChirho)?;
    if active_evidence_chirho.checkpoint_ref_chirho != expected_evidence_checkpoint_ref_chirho
        || active_evidence_chirho.checkpoint_chirho.phase_chirho
            != Gd7HeldEvidenceTransferPhaseChirho::CompleteChirho
    {
        return Err(ResidentGd7HeldAdoptionMaterializationRefusalChirho::StaleEvidenceChirho);
    }
    let active_branch_chirho = evidence_store_chirho
        .load_active_read_only_branch_evidence_chirho()?
        .ok_or(ResidentGd7HeldAdoptionMaterializationRefusalChirho::IncompleteEvidenceChirho)?;
    if active_branch_chirho.checkpoint_ref_chirho != expected_branch_checkpoint_ref_chirho {
        return Err(ResidentGd7HeldAdoptionMaterializationRefusalChirho::StaleEvidenceChirho);
    }
    let branch_checkpoint_chirho = &active_branch_chirho.checkpoint_chirho;
    let identity_chirho = &branch_checkpoint_chirho.transfer_identity_chirho;
    let identity_digest_chirho = gd7_held_evidence_transfer_identity_digest_chirho(identity_chirho)
        .map_err(|_error_chirho| {
            ResidentGd7HeldAdoptionMaterializationRefusalChirho::InvalidInputBindingChirho
        })?;
    let reconciliation_identity_digest_chirho =
        gd7_reconciliation_identity_digest_chirho(&identity_chirho.reconciliation_identity_chirho)
            .map_err(|_error_chirho| {
                ResidentGd7HeldAdoptionMaterializationRefusalChirho::InvalidInputBindingChirho
            })?;
    if sealed_plan_chirho.reconciliation_identity_digest_chirho
        != reconciliation_identity_digest_chirho
    {
        return Err(ResidentGd7HeldAdoptionMaterializationRefusalChirho::InvalidInputBindingChirho);
    }
    if sealed_plan_chirho.checkpoint_ref_chirho
        != identity_chirho.reconciliation_checkpoint_ref_chirho
        || branch_checkpoint_chirho.evidence_checkpoint_ref_chirho
            != active_evidence_chirho.checkpoint_ref_chirho
        || branch_checkpoint_chirho.held_view_checkpoint_ref_chirho
            != identity_chirho.held_view_transfer_checkpoint_ref_chirho
        || identity_digest_chirho != branch_checkpoint_chirho.transfer_identity_digest_chirho
    {
        return Err(ResidentGd7HeldAdoptionMaterializationRefusalChirho::InvalidInputBindingChirho);
    }
    let composition_chirho = evidence_store_chirho.verify_account_net_composition_chirho()?;
    let inputs_chirho = adoption_materialization_inputs_chirho(
        sealed_plan_chirho,
        identity_digest_chirho,
        &active_evidence_chirho,
        &active_branch_chirho,
        &composition_chirho,
    );
    let inputs_bytes_chirho = serde_json::to_vec(&inputs_chirho).map_err(|_error_chirho| {
        ResidentGd7HeldAdoptionMaterializationRefusalChirho::InvalidInputBindingChirho
    })?;
    let input_binding_digest_chirho = digest_bytes_chirho(&inputs_bytes_chirho);
    let staging_path_chirho = staging_journal_path_chirho(&input_binding_digest_chirho);
    let candidate_journal_path_chirho = candidate_journal_path_chirho(&input_binding_digest_chirho);
    let candidate_projection_path_chirho =
        candidate_projection_path_chirho(&input_binding_digest_chirho);
    let inputs_path_chirho = inputs_path_chirho(&input_binding_digest_chirho);

    cleanup_staging_chirho(ports_chirho.candidate_storage_chirho, &staging_path_chirho)?;
    match ports_chirho
        .candidate_storage_chirho
        .create_durable_chirho(&staging_path_chirho.0, &[])
        .map_err(|_error_chirho| {
            ResidentGd7HeldAdoptionMaterializationRefusalChirho::StorageChirho
        })? {
        CreateDurableOutcomeChirho::CreatedChirho => {}
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            return Err(
                ResidentGd7HeldAdoptionMaterializationRefusalChirho::ImmutableCollisionChirho,
            );
        }
    }

    let mut stream_refusal_chirho = None;
    let mut line_count_chirho = 0_u64;
    let mut byte_len_chirho = 0_u64;
    let branch_proof_chirho = evidence_store_chirho
        .visit_active_read_only_branch_canonical_lines_chirho(
            expected_branch_checkpoint_ref_chirho,
            |line_chirho| {
                if stream_refusal_chirho.is_some() {
                    return;
                }
                let next_line_count_chirho = line_count_chirho.checked_add(1);
                let next_byte_len_chirho = u64::try_from(line_chirho.len())
                    .ok()
                    .and_then(|line_len_chirho| line_len_chirho.checked_add(1))
                    .and_then(|line_len_chirho| byte_len_chirho.checked_add(line_len_chirho));
                let mut line_bytes_chirho = line_chirho.as_bytes().to_vec();
                line_bytes_chirho.push(b'\n');
                if next_line_count_chirho.is_none()
                    || next_byte_len_chirho.is_none()
                    || ports_chirho
                        .candidate_storage_chirho
                        .append_durable_chirho(&staging_path_chirho.0, &line_bytes_chirho)
                        .is_err()
                {
                    stream_refusal_chirho = Some(
                        ResidentGd7HeldAdoptionMaterializationRefusalChirho::CanonicalHistoryChirho,
                    );
                    return;
                }
                line_count_chirho = next_line_count_chirho.expect("checked above");
                byte_len_chirho = next_byte_len_chirho.expect("checked above");
            },
        );
    let branch_proof_chirho = match branch_proof_chirho {
        Ok(proof_chirho) => proof_chirho,
        Err(error_chirho) => {
            let _cleanup_chirho =
                cleanup_staging_chirho(ports_chirho.candidate_storage_chirho, &staging_path_chirho);
            return Err(error_chirho.into());
        }
    };
    if let Some(error_chirho) = stream_refusal_chirho {
        cleanup_staging_chirho(ports_chirho.candidate_storage_chirho, &staging_path_chirho)?;
        return Err(error_chirho);
    }
    let Some(candidate_record_count_chirho) = line_count_chirho.checked_sub(1) else {
        cleanup_staging_chirho(ports_chirho.candidate_storage_chirho, &staging_path_chirho)?;
        return Err(ResidentGd7HeldAdoptionMaterializationRefusalChirho::CanonicalHistoryChirho);
    };
    if candidate_record_count_chirho != branch_proof_chirho.canonical_record_count_chirho()
        || byte_len_chirho
            != ports_chirho
                .candidate_storage_chirho
                .object_len_chirho(&staging_path_chirho.0)
                .map_err(|_error_chirho| {
                    ResidentGd7HeldAdoptionMaterializationRefusalChirho::StorageChirho
                })?
                .ok_or(ResidentGd7HeldAdoptionMaterializationRefusalChirho::StorageChirho)?
    {
        cleanup_staging_chirho(ports_chirho.candidate_storage_chirho, &staging_path_chirho)?;
        return Err(ResidentGd7HeldAdoptionMaterializationRefusalChirho::CanonicalHistoryChirho);
    }

    let winner_journal_verifier_chirho = ReadOnlyWinnerJournalVerifierChirho {
        verifier_chirho: ports_chirho.winner_ledger_verifier_chirho,
    };
    let journal_chirho = match LedgerJournalChirho::open_read_only_full_chirho(
        JournalPortsChirho {
            storage_chirho: ports_chirho.candidate_storage_chirho,
            signer_chirho: &winner_journal_verifier_chirho,
            clock_chirho: ports_chirho.clock_chirho,
            membership_chirho: ports_chirho.membership_chirho,
            kind_registry_chirho: ports_chirho.kind_registry_chirho,
            authority_chirho: ports_chirho.authority_chirho,
        },
        staging_path_chirho.0.clone(),
        ports_chirho.cluster_id_chirho,
    ) {
        Ok(journal_chirho) => journal_chirho,
        Err(_error_chirho) => {
            cleanup_staging_chirho(ports_chirho.candidate_storage_chirho, &staging_path_chirho)?;
            return Err(
                ResidentGd7HeldAdoptionMaterializationRefusalChirho::JournalVerificationChirho,
            );
        }
    };
    let source_cut_chirho = journal_chirho.effect_intent_cut_chirho();
    let reconciliation_identity_chirho = &identity_chirho.reconciliation_identity_chirho;
    if journal_chirho.tail_seq_chirho() != candidate_record_count_chirho
        || source_cut_chirho.journal_genesis_digest_chirho.0
            != reconciliation_identity_chirho.winner_journal_genesis_digest_chirho
        || source_cut_chirho.tail_record_digest_chirho.0
            != reconciliation_identity_chirho
                .winner_journal_tail_chirho
                .record_digest_chirho
    {
        cleanup_staging_chirho(ports_chirho.candidate_storage_chirho, &staging_path_chirho)?;
        return Err(ResidentGd7HeldAdoptionMaterializationRefusalChirho::JournalVerificationChirho);
    }
    let projection_bytes_chirho =
        match AccountNetProjectionFoldChirho.fold_chirho(&VerifiedSourceStateChirho {
            journal_chirho: &journal_chirho,
        }) {
            Ok(bytes_chirho) => bytes_chirho,
            Err(_error_chirho) => {
                drop(journal_chirho);
                cleanup_staging_chirho(
                    ports_chirho.candidate_storage_chirho,
                    &staging_path_chirho,
                )?;
                return Err(
                    ResidentGd7HeldAdoptionMaterializationRefusalChirho::ProjectionFoldChirho,
                );
            }
        };
    let projection_bytes_chirho = projection_transform_chirho(projection_bytes_chirho);
    if projection_bytes_chirho != composition_chirho.canonical_projection_bytes_chirho() {
        cleanup_staging_chirho(ports_chirho.candidate_storage_chirho, &staging_path_chirho)?;
        return Err(ResidentGd7HeldAdoptionMaterializationRefusalChirho::CurrentViewMismatchChirho);
    }
    drop(journal_chirho);

    match active_inputs_match_chirho(
        evidence_store_chirho,
        &active_evidence_chirho,
        &active_branch_chirho,
    ) {
        Ok(true) => {}
        Ok(false) => {
            cleanup_staging_chirho(ports_chirho.candidate_storage_chirho, &staging_path_chirho)?;
            return Err(ResidentGd7HeldAdoptionMaterializationRefusalChirho::StaleEvidenceChirho);
        }
        Err(error_chirho) => {
            cleanup_staging_chirho(ports_chirho.candidate_storage_chirho, &staging_path_chirho)?;
            return Err(error_chirho);
        }
    }

    let journal_bytes_chirho = ports_chirho
        .candidate_storage_chirho
        .read_all_chirho(&staging_path_chirho.0)
        .map_err(|_error_chirho| {
            ResidentGd7HeldAdoptionMaterializationRefusalChirho::StorageChirho
        })?
        .ok_or(ResidentGd7HeldAdoptionMaterializationRefusalChirho::StorageChirho)?;
    let candidate_journal_digest_chirho = digest_bytes_chirho(&journal_bytes_chirho);
    let candidate_projection_digest_chirho = digest_bytes_chirho(&projection_bytes_chirho);
    create_exact_digest_bound_chirho(
        ports_chirho.candidate_storage_chirho,
        &candidate_journal_path_chirho,
        &journal_bytes_chirho,
        &candidate_journal_digest_chirho,
    )?;
    create_exact_digest_bound_chirho(
        ports_chirho.candidate_storage_chirho,
        &candidate_projection_path_chirho,
        &projection_bytes_chirho,
        &candidate_projection_digest_chirho,
    )?;
    create_exact_digest_bound_chirho(
        ports_chirho.candidate_storage_chirho,
        &inputs_path_chirho,
        &inputs_bytes_chirho,
        &input_binding_digest_chirho,
    )?;
    cleanup_staging_chirho(ports_chirho.candidate_storage_chirho, &staging_path_chirho)?;

    let projection_len_chirho =
        u64::try_from(projection_bytes_chirho.len()).map_err(|_error_chirho| {
            ResidentGd7HeldAdoptionMaterializationRefusalChirho::ArithmeticOverflowChirho
        })?;
    if !active_inputs_match_chirho(
        evidence_store_chirho,
        &active_evidence_chirho,
        &active_branch_chirho,
    )? {
        return Err(ResidentGd7HeldAdoptionMaterializationRefusalChirho::StaleEvidenceChirho);
    }
    Ok(ResidentGd7HeldPreparedAdoptionChirho {
        input_binding_digest_chirho,
        plan_checkpoint_ref_chirho: sealed_plan_chirho.checkpoint_ref_chirho.clone(),
        evidence_checkpoint_ref_chirho: expected_evidence_checkpoint_ref_chirho.to_owned(),
        read_only_branch_checkpoint_ref_chirho: expected_branch_checkpoint_ref_chirho.to_owned(),
        candidate_journal_path_chirho,
        candidate_journal_digest_chirho,
        candidate_journal_byte_len_chirho: byte_len_chirho,
        candidate_record_count_chirho,
        candidate_projection_path_chirho,
        candidate_projection_digest_chirho,
        candidate_projection_byte_len_chirho: projection_len_chirho,
        candidate_projection_row_count_chirho: composition_chirho.matched_row_count_chirho(),
    })
}

fn active_inputs_match_chirho(
    evidence_store_chirho: &Gd7HeldEvidenceTransferStoreChirho<'_>,
    expected_evidence_chirho: &crate::reconciliation_chirho::ActiveGd7HeldEvidenceTransferChirho,
    expected_branch_chirho: &crate::reconciliation_chirho::ActiveGd7ReadOnlyBranchChirho,
) -> Result<bool, ResidentGd7HeldAdoptionMaterializationRefusalChirho> {
    Ok(
        evidence_store_chirho.load_active_chirho()?.as_ref() == Some(expected_evidence_chirho)
            && evidence_store_chirho
                .load_active_read_only_branch_evidence_chirho()?
                .as_ref()
                == Some(expected_branch_chirho),
    )
}

#[cfg(test)]
pub(crate) fn gd7_adoption_staging_journal_path_for_test_chirho(
    input_binding_digest_chirho: &str,
) -> StoragePathChirho {
    staging_journal_path_chirho(input_binding_digest_chirho).0
}

fn staging_journal_path_chirho(
    input_binding_digest_chirho: &str,
) -> Gd7AdoptionStagingJournalPathChirho {
    Gd7AdoptionStagingJournalPathChirho(materialization_path_chirho(
        "staging-journals-chirho",
        input_binding_digest_chirho,
        "jsonl",
    ))
}

pub(super) fn candidate_journal_path_chirho(
    input_binding_digest_chirho: &str,
) -> StoragePathChirho {
    materialization_path_chirho(
        "candidate-journals-chirho",
        input_binding_digest_chirho,
        "jsonl",
    )
}

pub(super) fn candidate_projection_path_chirho(
    input_binding_digest_chirho: &str,
) -> StoragePathChirho {
    materialization_path_chirho(
        "candidate-account-net-projections-chirho",
        input_binding_digest_chirho,
        "json",
    )
}

pub(super) fn inputs_path_chirho(input_binding_digest_chirho: &str) -> StoragePathChirho {
    materialization_path_chirho("input-bindings-chirho", input_binding_digest_chirho, "json")
}

fn materialization_path_chirho(
    family_chirho: &str,
    digest_chirho: &str,
    extension_chirho: &str,
) -> StoragePathChirho {
    StoragePathChirho::new_chirho(format!(
        "{GD7_ADOPTION_MATERIALIZATION_NAMESPACE_CHIRHO}/{family_chirho}/{}/{}/{digest_chirho}.{extension_chirho}",
        &digest_chirho[..2],
        &digest_chirho[2..4],
    ))
}

fn cleanup_staging_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    staging_path_chirho: &Gd7AdoptionStagingJournalPathChirho,
) -> Result<(), ResidentGd7HeldAdoptionMaterializationRefusalChirho> {
    storage_chirho
        .remove_chirho(&staging_path_chirho.0)
        .map_err(|_error_chirho| ResidentGd7HeldAdoptionMaterializationRefusalChirho::StorageChirho)
}

fn create_exact_digest_bound_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    bytes_chirho: &[u8],
    expected_digest_chirho: &str,
) -> Result<(), ResidentGd7HeldAdoptionMaterializationRefusalChirho> {
    match storage_chirho
        .create_durable_chirho(path_chirho, bytes_chirho)
        .map_err(|_error_chirho| {
            ResidentGd7HeldAdoptionMaterializationRefusalChirho::StorageChirho
        })? {
        CreateDurableOutcomeChirho::CreatedChirho => Ok(()),
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_chirho = storage_chirho
                .read_all_chirho(path_chirho)
                .map_err(|_error_chirho| {
                    ResidentGd7HeldAdoptionMaterializationRefusalChirho::StorageChirho
                })?
                .ok_or(
                    ResidentGd7HeldAdoptionMaterializationRefusalChirho::ImmutableCollisionChirho,
                )?;
            if existing_chirho.len() == bytes_chirho.len()
                && digest_bytes_chirho(&existing_chirho) == expected_digest_chirho
            {
                Ok(())
            } else {
                Err(ResidentGd7HeldAdoptionMaterializationRefusalChirho::ImmutableCollisionChirho)
            }
        }
    }
}

pub(super) fn digest_bytes_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}
