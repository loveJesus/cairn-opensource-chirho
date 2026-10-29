// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Actor-side orchestration for the crash-atomic held adoption selector.
//!
//! The durable schema and restart verifier remain in `adoption_commit_chirho`; this module keeps
//! election and pinned-port assembly out of the coordinator mailbox loop. It does not move a served
//! ref, release the reconciliation hold, or mint authority.
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

use super::adoption_commit_chirho::{
    commit_or_reload_gd7_held_adoption_chirho, verify_active_gd7_held_adoption_chirho,
    Gd7HeldAdoptionCommitPortsChirho,
};
use super::*;
use crate::reconciliation_chirho::{
    claim_verified_gd7_losing_effect_obligation_chirho, gd7_reconciliation_identity_digest_chirho,
    load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho,
    verify_gd7_sealed_plan_obligation_at_checkpoint_chirho, Gd7EffectProofPortsChirho,
    Gd7LedgerRecordVerifierPortChirho, Gd7LosingEffectObligationMintRefusalChirho,
    Gd7LosingEffectObligationSelectorChirho, Gd7PlanRefusalChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
    MintedGd7LosingEffectObligationChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{LedgerClockPortChirho, LedgerStoragePortChirho};
use std::error::Error;
use std::fmt;

pub(super) struct ResidentGd7HeldAdoptionActorPortsChirho<'a> {
    pub(super) authority_storage_chirho: &'a FsLedgerStorageChirho,
    pub(super) candidate_storage_chirho: &'a FsLedgerStorageChirho,
    pub(super) held_verifier_chirho: &'a PinnedNodeGd7VerifierChirho,
    pub(super) held_signer_chirho: Option<&'a ExistingNodeGd7SignerChirho>,
    pub(super) held_ledger_verifiers_chirho: &'a HostLedgerHeldVerifiersChirho,
    pub(super) elector_chirho: &'a RaftWriterElectorChirho,
    pub(super) group_chirho: &'a ConsistencyGroupIdChirho,
    pub(super) group_digest_chirho: &'a str,
    pub(super) local_node_chirho: &'a NodeIdChirho,
    pub(super) losing_tail_chirho: &'a VerifiedLosingJournalTailChirho,
    pub(super) clock_chirho: &'a ResidentLedgerClockChirho,
    pub(super) membership_chirho: &'a HeldReadOnlyMembershipChirho,
    pub(super) kind_registry_chirho: &'a HeldReadOnlyKindRegistryChirho,
    pub(super) authority_chirho: &'a HeldReadOnlyAuthorityVerifierChirho,
    pub(super) cluster_id_chirho: &'a ClusterIdChirho,
}

pub(crate) struct ResidentGd7HeldObligationMintActorPortsChirho<'ports_chirho> {
    pub authority_storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    pub candidate_storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    pub held_verifier_chirho: &'ports_chirho dyn Gd7ReconciliationVerifierPortChirho,
    pub held_signer_chirho: Option<&'ports_chirho dyn Gd7ReconciliationSignerPortChirho>,
    pub winner_control_verifier_chirho: &'ports_chirho dyn Gd7ReconciliationVerifierPortChirho,
    pub winner_ledger_verifier_chirho: &'ports_chirho dyn Gd7LedgerRecordVerifierPortChirho,
    pub effect_proof_ports_chirho: Gd7EffectProofPortsChirho<'ports_chirho>,
    pub clock_chirho: &'ports_chirho dyn LedgerClockPortChirho,
    pub membership_chirho: &'ports_chirho dyn MembershipViewChirho,
    pub kind_registry_chirho: &'ports_chirho dyn KindRegistryViewChirho,
    pub authority_chirho: &'ports_chirho dyn AuthorityVerifierViewChirho,
    pub cluster_id_chirho: &'ports_chirho ClusterIdChirho,
    pub group_digest_chirho: &'ports_chirho str,
}

/// Why one actor-owned obligation mint refused, at the granularity a caller must act on.
///
/// WIDENED FROM `pub(crate)` TO `pub` FOR THE SAME REASON ITS NEIGHBOUR
/// `Gd7CompensationCompositionRefusalChirho` ALREADY CARRIES. It is the payload of a `pub` mailbox
/// refusal, so leaving it crate-private both stands a `private_interfaces` warning in a zero-warning
/// gate and — the part that matters — leaves a caller unable to NAME the variant it must branch on.
/// On this path that is not a nicety: `AdoptionChangedAfterMintChirho { receipt_ref_chirho }` means a
/// durable receipt EXISTS, and a caller that can only see "some mint refusal" will retry it and mint
/// the same obligation twice.
///
/// The type is public; the AUTHORITY is not. Nothing here lets a caller construct a mint, supply a
/// port, or name a subject — the port bundle stays crate-internal.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum ResidentGd7HeldObligationMintRefusalChirho {
    LiveReconciliationNotConfiguredChirho,
    ActiveAdoptionUnavailableChirho,
    InvalidWinnerControlVerifierChirho,
    AdoptionChirho(ResidentGd7HeldAdoptionCommitRefusalChirho),
    PlanChirho(Gd7PlanRefusalChirho),
    MintChirho(Gd7LosingEffectObligationMintRefusalChirho),
    AdoptionChangedBeforeMintChirho,
    AdoptionChangedAfterMintChirho { receipt_ref_chirho: String },
}

impl fmt::Display for ResidentGd7HeldObligationMintRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LiveReconciliationNotConfiguredChirho => formatter_chirho
                .write_str("GD7 losing-effect obligation mint requires live reconciliation"),
            Self::ActiveAdoptionUnavailableChirho => formatter_chirho
                .write_str("GD7 losing-effect obligation mint requires an active adopted selector"),
            Self::InvalidWinnerControlVerifierChirho => formatter_chirho
                .write_str("GD7 losing-effect obligation mint cannot bind the winner control verifier"),
            Self::AdoptionChirho(error_chirho) => {
                write!(formatter_chirho, "GD7 adopted selector refused obligation mint: {error_chirho}")
            }
            Self::PlanChirho(error_chirho) => {
                write!(formatter_chirho, "GD7 sealed plan refused obligation mint: {error_chirho}")
            }
            Self::MintChirho(error_chirho) => {
                write!(formatter_chirho, "GD7 losing-effect obligation mint refused: {error_chirho}")
            }
            Self::AdoptionChangedBeforeMintChirho => formatter_chirho
                .write_str("GD7 adopted selector changed before durable obligation mint"),
            Self::AdoptionChangedAfterMintChirho { receipt_ref_chirho } => write!(
                formatter_chirho,
                "GD7 adopted selector changed after durable obligation mint receipt {receipt_ref_chirho}; receipt is awaiting verified item-5b resume"
            ),
        }
    }
}

impl Error for ResidentGd7HeldObligationMintRefusalChirho {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::AdoptionChirho(error_chirho) => Some(error_chirho),
            Self::PlanChirho(error_chirho) => Some(error_chirho),
            Self::MintChirho(error_chirho) => Some(error_chirho),
            _ => None,
        }
    }
}

impl From<ResidentGd7HeldAdoptionCommitRefusalChirho>
    for ResidentGd7HeldObligationMintRefusalChirho
{
    fn from(error_chirho: ResidentGd7HeldAdoptionCommitRefusalChirho) -> Self {
        Self::AdoptionChirho(error_chirho)
    }
}

impl From<Gd7PlanRefusalChirho> for ResidentGd7HeldObligationMintRefusalChirho {
    fn from(error_chirho: Gd7PlanRefusalChirho) -> Self {
        Self::PlanChirho(error_chirho)
    }
}

impl From<Gd7LosingEffectObligationMintRefusalChirho>
    for ResidentGd7HeldObligationMintRefusalChirho
{
    fn from(error_chirho: Gd7LosingEffectObligationMintRefusalChirho) -> Self {
        Self::MintChirho(error_chirho)
    }
}

pub(super) fn verify_actor_owned_gd7_held_adoption_startup_chirho(
    expected_identity_chirho: &Gd7ReconciliationIdentityChirho,
    active_chirho: &ActiveGd7ReconciliationChirho,
    ports_chirho: &ResidentGd7HeldAdoptionActorPortsChirho<'_>,
) -> Result<()> {
    let held_signer_chirho = ports_chirho
        .held_signer_chirho
        .ok_or_else(|| anyhow!("adopted held GD7 checkpoint requires schema v4"))?;
    let winner_control_verifier_chirho = PinnedNodeGd7VerifierChirho::new_chirho(NodeIdChirho(
        expected_identity_chirho.winner_node_chirho.clone(),
    ))?;
    verify_active_gd7_held_adoption_chirho(
        expected_identity_chirho,
        &active_chirho
            .checkpoint_chirho
            .winner_fork_witness_object_digest_chirho,
        &Gd7HeldAdoptionCommitPortsChirho {
            authority_storage_chirho: ports_chirho.authority_storage_chirho,
            candidate_storage_chirho: ports_chirho.candidate_storage_chirho,
            held_signer_chirho,
            winner_control_verifier_chirho: &winner_control_verifier_chirho,
            winner_ledger_verifier_chirho: &ports_chirho
                .held_ledger_verifiers_chirho
                .journal_chirho,
            clock_chirho: ports_chirho.clock_chirho,
            membership_chirho: ports_chirho.membership_chirho,
            kind_registry_chirho: ports_chirho.kind_registry_chirho,
            authority_chirho: ports_chirho.authority_chirho,
            cluster_id_chirho: ports_chirho.cluster_id_chirho,
        },
    )
    .map_err(|error_chirho| anyhow!(error_chirho))?;
    Ok(())
}

pub(super) fn commit_or_reload_actor_owned_gd7_held_adoption_chirho(
    expected_identity_chirho: &Gd7ReconciliationIdentityChirho,
    prepared_chirho: &ResidentGd7HeldPreparedAdoptionChirho,
    ports_chirho: &ResidentGd7HeldAdoptionActorPortsChirho<'_>,
) -> std::result::Result<
    ResidentGd7HeldAdoptionCommitOutcomeChirho,
    ResidentGd7HeldCoordinatorRefusalChirho,
> {
    inspect_held_coordinate_chirho(
        ports_chirho.authority_storage_chirho,
        ports_chirho.held_verifier_chirho,
        ports_chirho.elector_chirho,
        ports_chirho.group_chirho,
        ports_chirho.group_digest_chirho,
        ports_chirho.local_node_chirho,
        expected_identity_chirho,
        ports_chirho.losing_tail_chirho,
        verify_held_historical_mutation_election_chirho,
    )?;
    let held_signer_chirho = ports_chirho
        .held_signer_chirho
        .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::LiveReconciliationNotConfiguredChirho)?;
    let active_chirho = load_authenticated_active_gd7_reconciliation_for_group_chirho(
        ports_chirho.authority_storage_chirho,
        ports_chirho.held_verifier_chirho,
        ports_chirho.group_digest_chirho,
    )
    .map_err(|_error_chirho| ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChirho)?
    .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChirho)?;
    if active_chirho.checkpoint_chirho.identity_chirho != *expected_identity_chirho {
        return Err(ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChangedIdentityChirho);
    }
    let precommit_election_verifier_chirho: HeldIdentityElectionVerifierChirho =
        if active_chirho.checkpoint_chirho.state_chirho.phase_chirho
            == Gd7ReconciliationPhaseChirho::AdoptedHeldChirho
        {
            // Exact retry is read-only, but full restart verification below must still earn it.
            verify_held_read_only_election_observation_chirho
        } else {
            verify_held_historical_mutation_election_chirho
        };
    inspect_held_coordinate_chirho(
        ports_chirho.authority_storage_chirho,
        ports_chirho.held_verifier_chirho,
        ports_chirho.elector_chirho,
        ports_chirho.group_chirho,
        ports_chirho.group_digest_chirho,
        ports_chirho.local_node_chirho,
        expected_identity_chirho,
        ports_chirho.losing_tail_chirho,
        precommit_election_verifier_chirho,
    )?;
    let winner_control_verifier_chirho = PinnedNodeGd7VerifierChirho::new_chirho(NodeIdChirho(
        expected_identity_chirho.winner_node_chirho.clone(),
    ))
    .map_err(|_error_chirho| {
        ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChangedIdentityChirho
    })?;
    let outcome_chirho = commit_or_reload_gd7_held_adoption_chirho(
        expected_identity_chirho,
        &active_chirho
            .checkpoint_chirho
            .winner_fork_witness_object_digest_chirho,
        prepared_chirho,
        &Gd7HeldAdoptionCommitPortsChirho {
            authority_storage_chirho: ports_chirho.authority_storage_chirho,
            candidate_storage_chirho: ports_chirho.candidate_storage_chirho,
            held_signer_chirho,
            winner_control_verifier_chirho: &winner_control_verifier_chirho,
            winner_ledger_verifier_chirho: &ports_chirho
                .held_ledger_verifiers_chirho
                .journal_chirho,
            clock_chirho: ports_chirho.clock_chirho,
            membership_chirho: ports_chirho.membership_chirho,
            kind_registry_chirho: ports_chirho.kind_registry_chirho,
            authority_chirho: ports_chirho.authority_chirho,
            cluster_id_chirho: ports_chirho.cluster_id_chirho,
        },
    )?;
    inspect_held_coordinate_chirho(
        ports_chirho.authority_storage_chirho,
        ports_chirho.held_verifier_chirho,
        ports_chirho.elector_chirho,
        ports_chirho.group_chirho,
        ports_chirho.group_digest_chirho,
        ports_chirho.local_node_chirho,
        expected_identity_chirho,
        ports_chirho.losing_tail_chirho,
        verify_held_read_only_election_observation_chirho,
    )?;
    Ok(outcome_chirho)
}

/// Mint one exact actor-owned GD7 losing-effect obligation, with every verification inward.
///
/// # THE `dead_code` ALLOW IS GONE, BY CONSUMPTION
///
/// This function carried `#[allow(dead_code, reason = "item 5a deliberately has no production
/// caller until item 5b composes mint and consume")]`. That allow named its own future, and this is
/// that moment: the held coordinator's `MintLosingEffectObligationChirho` command is the production
/// caller, so the allow died by being CONSUMED rather than by being suppressed — the same way
/// `compose_gd7_compensation_chirho`'s did when the success ladder became its caller.
///
/// The function stays crate-internal on purpose. What became public is the mailbox command, whose
/// request carries a selector only; the port bundle, the held signer, and the adoption CAS checks
/// all remain inward of the mailbox send, so widening the trigger did not widen the authority.
///
/// # WHAT THIS STILL DOES NOT DO
///
/// It does not resume an awaiting receipt, fence the sink, or consume the affine value — item 5b
/// owns that. A refusal carrying `receipt_ref_chirho` therefore reports a durable receipt with no
/// consumer yet, which is a state the caller must not paper over by retrying.
pub(crate) fn mint_actor_owned_gd7_losing_effect_obligation_chirho(
    expected_identity_chirho: &Gd7ReconciliationIdentityChirho,
    selector_chirho: &Gd7LosingEffectObligationSelectorChirho,
    ports_chirho: &ResidentGd7HeldObligationMintActorPortsChirho<'_>,
) -> std::result::Result<
    MintedGd7LosingEffectObligationChirho,
    ResidentGd7HeldObligationMintRefusalChirho,
> {
    mint_actor_owned_gd7_losing_effect_obligation_internal_chirho(
        expected_identity_chirho,
        selector_chirho,
        ports_chirho,
        |plan_checkpoint_ref_chirho, plan_checkpoint_chirho, selector_chirho| {
            verify_gd7_sealed_plan_obligation_at_checkpoint_chirho(
                ports_chirho.authority_storage_chirho,
                ports_chirho
                    .held_signer_chirho
                    .ok_or(Gd7PlanRefusalChirho::SigningChirho)?,
                ports_chirho.winner_ledger_verifier_chirho,
                &ports_chirho.effect_proof_ports_chirho,
                plan_checkpoint_ref_chirho,
                plan_checkpoint_chirho,
                selector_chirho,
            )
        },
        |_minted_chirho| {},
    )
}

#[cfg(test)]
pub(crate) fn mint_actor_owned_gd7_losing_effect_obligation_with_hooks_for_test_chirho(
    expected_identity_chirho: &Gd7ReconciliationIdentityChirho,
    selector_chirho: &Gd7LosingEffectObligationSelectorChirho,
    ports_chirho: &ResidentGd7HeldObligationMintActorPortsChirho<'_>,
    verify_obligation_chirho: impl FnOnce(
        &str,
        &crate::reconciliation_chirho::Gd7ReconciliationCheckpointChirho,
        &Gd7LosingEffectObligationSelectorChirho,
    ) -> std::result::Result<
        crate::reconciliation_chirho::VerifiedGd7SealedPlanObligationChirho,
        Gd7PlanRefusalChirho,
    >,
    after_mint_chirho: impl FnOnce(&MintedGd7LosingEffectObligationChirho),
) -> std::result::Result<
    MintedGd7LosingEffectObligationChirho,
    ResidentGd7HeldObligationMintRefusalChirho,
> {
    mint_actor_owned_gd7_losing_effect_obligation_internal_chirho(
        expected_identity_chirho,
        selector_chirho,
        ports_chirho,
        verify_obligation_chirho,
        after_mint_chirho,
    )
}

fn mint_actor_owned_gd7_losing_effect_obligation_internal_chirho(
    expected_identity_chirho: &Gd7ReconciliationIdentityChirho,
    selector_chirho: &Gd7LosingEffectObligationSelectorChirho,
    ports_chirho: &ResidentGd7HeldObligationMintActorPortsChirho<'_>,
    verify_obligation_chirho: impl FnOnce(
        &str,
        &crate::reconciliation_chirho::Gd7ReconciliationCheckpointChirho,
        &Gd7LosingEffectObligationSelectorChirho,
    ) -> std::result::Result<
        crate::reconciliation_chirho::VerifiedGd7SealedPlanObligationChirho,
        Gd7PlanRefusalChirho,
    >,
    after_mint_chirho: impl FnOnce(&MintedGd7LosingEffectObligationChirho),
) -> std::result::Result<
    MintedGd7LosingEffectObligationChirho,
    ResidentGd7HeldObligationMintRefusalChirho,
> {
    let held_signer_chirho = ports_chirho
        .held_signer_chirho
        .ok_or(ResidentGd7HeldObligationMintRefusalChirho::LiveReconciliationNotConfiguredChirho)?;
    let active_chirho = load_authenticated_active_gd7_reconciliation_for_group_chirho(
        ports_chirho.authority_storage_chirho,
        ports_chirho.held_verifier_chirho,
        ports_chirho.group_digest_chirho,
    )
    .map_err(|_error_chirho| {
        ResidentGd7HeldObligationMintRefusalChirho::ActiveAdoptionUnavailableChirho
    })?
    .ok_or(ResidentGd7HeldObligationMintRefusalChirho::ActiveAdoptionUnavailableChirho)?;
    if active_chirho.checkpoint_chirho.identity_chirho != *expected_identity_chirho
        || active_chirho.checkpoint_chirho.state_chirho.phase_chirho
            != Gd7ReconciliationPhaseChirho::AdoptedHeldChirho
    {
        return Err(ResidentGd7HeldObligationMintRefusalChirho::ActiveAdoptionUnavailableChirho);
    }
    if ports_chirho.winner_control_verifier_chirho.key_id_chirho()
        != expected_identity_chirho.winner_node_chirho
    {
        return Err(ResidentGd7HeldObligationMintRefusalChirho::InvalidWinnerControlVerifierChirho);
    }
    let adoption_ports_chirho = Gd7HeldAdoptionCommitPortsChirho {
        authority_storage_chirho: ports_chirho.authority_storage_chirho,
        candidate_storage_chirho: ports_chirho.candidate_storage_chirho,
        held_signer_chirho,
        winner_control_verifier_chirho: ports_chirho.winner_control_verifier_chirho,
        winner_ledger_verifier_chirho: ports_chirho.winner_ledger_verifier_chirho,
        clock_chirho: ports_chirho.clock_chirho,
        membership_chirho: ports_chirho.membership_chirho,
        kind_registry_chirho: ports_chirho.kind_registry_chirho,
        authority_chirho: ports_chirho.authority_chirho,
        cluster_id_chirho: ports_chirho.cluster_id_chirho,
    };
    let snapshot_before_chirho = verify_active_gd7_held_adoption_chirho(
        expected_identity_chirho,
        &active_chirho
            .checkpoint_chirho
            .winner_fork_witness_object_digest_chirho,
        &adoption_ports_chirho,
    )?;
    let plan_checkpoint_ref_chirho = snapshot_before_chirho.plan_checkpoint_ref_chirho();
    let plan_checkpoint_chirho = load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho(
        ports_chirho.authority_storage_chirho,
        held_signer_chirho,
        plan_checkpoint_ref_chirho,
    )
    .map_err(|_error_chirho| {
        ResidentGd7HeldObligationMintRefusalChirho::ActiveAdoptionUnavailableChirho
    })?;
    if plan_checkpoint_chirho.identity_chirho != *expected_identity_chirho {
        return Err(ResidentGd7HeldObligationMintRefusalChirho::AdoptionChangedBeforeMintChirho);
    }
    let sealed_plan_ref_chirho = plan_checkpoint_chirho
        .state_chirho
        .sealed_plan_ref_chirho
        .as_deref()
        .ok_or(ResidentGd7HeldObligationMintRefusalChirho::ActiveAdoptionUnavailableChirho)?;
    let verified_obligation_chirho = verify_obligation_chirho(
        plan_checkpoint_ref_chirho,
        &plan_checkpoint_chirho,
        selector_chirho,
    )?;
    let snapshot_before_claim_chirho = verify_active_gd7_held_adoption_chirho(
        expected_identity_chirho,
        &active_chirho
            .checkpoint_chirho
            .winner_fork_witness_object_digest_chirho,
        &adoption_ports_chirho,
    )
    .map_err(|_error_chirho| {
        ResidentGd7HeldObligationMintRefusalChirho::AdoptionChangedBeforeMintChirho
    })?;
    if snapshot_before_claim_chirho != snapshot_before_chirho {
        return Err(ResidentGd7HeldObligationMintRefusalChirho::AdoptionChangedBeforeMintChirho);
    }
    let reconciliation_identity_digest_chirho = gd7_reconciliation_identity_digest_chirho(
        expected_identity_chirho,
    )
    .map_err(|_error_chirho| {
        ResidentGd7HeldObligationMintRefusalChirho::ActiveAdoptionUnavailableChirho
    })?;
    let minted_chirho = claim_verified_gd7_losing_effect_obligation_chirho(
        ports_chirho.authority_storage_chirho,
        held_signer_chirho,
        snapshot_before_chirho.checkpoint_ref_chirho(),
        plan_checkpoint_ref_chirho,
        sealed_plan_ref_chirho,
        &reconciliation_identity_digest_chirho,
        expected_identity_chirho.winner_term_chirho,
        verified_obligation_chirho,
    )?;
    after_mint_chirho(&minted_chirho);
    let receipt_ref_chirho = minted_chirho.receipt_ref_chirho().to_owned();
    let adoption_still_exact_chirho = verify_active_gd7_held_adoption_chirho(
        expected_identity_chirho,
        &active_chirho
            .checkpoint_chirho
            .winner_fork_witness_object_digest_chirho,
        &adoption_ports_chirho,
    )
    .is_ok_and(|snapshot_after_chirho| snapshot_after_chirho == snapshot_before_chirho);
    if !adoption_still_exact_chirho {
        return Err(
            ResidentGd7HeldObligationMintRefusalChirho::AdoptionChangedAfterMintChirho {
                receipt_ref_chirho,
            },
        );
    }
    Ok(minted_chirho)
}
