// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! One O(page) GD7 plan reduction transition.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

use cairn_effect_commit_chirho::minimal_warrant_chirho::{
    verify_minimal_warrant_line_chirho, MinimalEffectWarrantChirho,
};

use super::contract_chirho::{
    Gd7EffectEvidenceReaderPortChirho, Gd7EffectLineageChirho, Gd7EffectPlanObligationChirho,
    Gd7EffectPlanObligationKindChirho, Gd7PlanPageDriveOutcomeChirho, Gd7PlanPageFactCountsChirho,
    Gd7PlanRefusalChirho, Gd7ReconciliationPlanPageChirho, Gd7TerminalDispositionChirho,
    VerifiedGd7ReconciliationPlanPageChirho, GD7_RECONCILIATION_PLAN_PAGE_SCHEMA_V1_CHIRHO,
    MAX_GD7_EFFECT_INTENT_LINE_BYTES_CHIRHO, MAX_GD7_EFFECT_TERMINAL_LINE_BYTES_CHIRHO,
    MAX_GD7_RECONCILIATION_PLAN_PAGE_BYTES_CHIRHO,
};
use super::marker_chirho::{
    load_matching_terminal_marker_required_chirho, load_terminal_marker_optional_chirho,
    persist_or_load_terminal_marker_chirho, Gd7TerminalMarkerInputChirho,
};
use super::object_chirho::{
    digest_bytes_chirho, gd7_reconciliation_plan_page_path_chirho, persist_immutable_chirho,
    read_bounded_required_chirho,
};
use crate::reconciliation_chirho::contract_chirho::{
    is_bounded_label_chirho, is_lower_hex_digest_chirho, MAX_GD7_RECONCILIATION_LABEL_BYTES_CHIRHO,
};
use crate::reconciliation_chirho::manifest_chirho::{
    load_verified_gd7_losing_manifest_page_chirho, VerifiedGd7LosingManifestPageChirho,
};
use crate::reconciliation_chirho::store_chirho::{
    gd7_reconciliation_identity_digest_chirho, ActiveGd7ReconciliationChirho,
    Gd7ReconciliationStoreChirho,
};
use crate::reconciliation_chirho::winner_witness_chirho::AuthenticatedGd7DeposedForkObservationChirho;
use crate::reconciliation_chirho::{
    Gd7ReconciliationCheckpointStateChirho, Gd7ReconciliationIdentityChirho,
    Gd7ReconciliationPhaseChirho, Gd7ReconciliationSignerPortChirho,
    Gd7ReconciliationVerifierPortChirho,
};
// GD7 reads the WarrantChirho family; the full intent stays journal/IntentChirho-only. If an
// IntentChirho full-line import reappears on this warrant-read path, the privacy narrowing regressed.
use cairn_effect_commit_chirho::intent_chirho::{
    effect_compensation_key_chirho, parse_effect_compensation_key_chirho,
    EffectIntentSignerPortChirho,
};
use cairn_effect_commit_chirho::terminal_chirho::{
    verify_effect_terminal_outcome_line_chirho,
    EffectTerminalDispositionChirho as SignedEffectTerminalDispositionChirho,
    EffectTerminalSignerPortChirho,
};
use cairn_ledger_log_chirho::effect_record_fact_chirho::{
    classify_effect_record_fact_chirho, EffectHoldLineageChirho, EffectRecordFactChirho,
    EffectTerminalFactDispositionChirho,
};
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::record_chirho::{
    EscrowControlChirho, LedgerRecordChirho, LegDeltaChirho,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedIntentCoordinatesChirho {
    lineage_chirho: Gd7EffectLineageChirho,
    expected_control_saga_id_chirho: DigestChirho,
    warrant_chirho: MinimalEffectWarrantChirho,
}

pub struct Gd7EffectProofPortsChirho<'ports_chirho> {
    evidence_chirho: &'ports_chirho dyn Gd7EffectEvidenceReaderPortChirho,
    intent_verifier_chirho: &'ports_chirho dyn EffectIntentSignerPortChirho,
    terminal_verifier_chirho: &'ports_chirho dyn EffectTerminalSignerPortChirho,
}

impl<'ports_chirho> Gd7EffectProofPortsChirho<'ports_chirho> {
    pub fn new_chirho(
        evidence_chirho: &'ports_chirho dyn Gd7EffectEvidenceReaderPortChirho,
        intent_verifier_chirho: &'ports_chirho dyn EffectIntentSignerPortChirho,
        terminal_verifier_chirho: &'ports_chirho dyn EffectTerminalSignerPortChirho,
    ) -> Self {
        Self {
            evidence_chirho,
            intent_verifier_chirho,
            terminal_verifier_chirho,
        }
    }
}

struct TerminalBindingInputChirho<'input_chirho> {
    record_chirho: &'input_chirho LedgerRecordChirho,
    intent_ref_chirho: &'input_chirho DigestChirho,
    outcome_ref_chirho: &'input_chirho DigestChirho,
    control_chirho: &'input_chirho EscrowControlChirho,
    disposition_chirho: Gd7TerminalDispositionChirho,
    coordinates_chirho: &'input_chirho VerifiedIntentCoordinatesChirho,
}

struct ObligationInputChirho<'input_chirho> {
    kind_chirho: Gd7EffectPlanObligationKindChirho,
    intent_ref_chirho: &'input_chirho DigestChirho,
    coordinates_chirho: &'input_chirho VerifiedIntentCoordinatesChirho,
    control_chirho: EscrowControlChirho,
    outcome_ref_chirho: Option<DigestChirho>,
    source_record_chirho: &'input_chirho LedgerRecordChirho,
    source_record_digest_chirho: &'input_chirho str,
    terminal_marker_object_digest_chirho: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ReducedPlanPageLocalChirho {
    pub(super) fact_counts_chirho: Gd7PlanPageFactCountsChirho,
    pub(super) obligations_newest_first_chirho: Vec<Gd7EffectPlanObligationChirho>,
    pub(super) terminal_marker_object_digests_newest_first_chirho: Vec<String>,
}

/// THE SIGNING CAPABILITY TRAVELS AS DATA, IN THE VARIANT THAT NEEDS IT.
///
/// This carries the signer instead of the reducer taking one alongside a mode flag, and the
/// difference is a capability boundary rather than a style choice: the read-only arm has NO SIGNER
/// IN SCOPE TO CALL. Before this, both modes shared one `&dyn Gd7ReconciliationSignerPortChirho`
/// parameter typed for the wider of them, so the read-only sealed-plan enumeration chain — walked by
/// a restore path — demanded a signing key it provably never used. A caller that cannot sign should
/// not have to hold a key to make the call.
///
/// SCOPE, stated because it is easy to overclaim: this makes the LOCAL state unrepresentable, not
/// the closure. Nothing here stops a future edit adding a signer as a SEPARATE parameter to this
/// module's functions. The compile witness over the complete read-only chain is what covers that;
/// the two are different instruments and neither substitutes for the other.
#[derive(Clone, Copy)]
enum TerminalMarkerAccessChirho<'access_chirho> {
    PersistOrLoadChirho {
        signer_chirho: &'access_chirho dyn Gd7ReconciliationSignerPortChirho,
    },
    LoadRequiredChirho,
}

/// Reduce exactly the one manifest page not yet named by the active plan head.
///
/// Manifest and plan progress alternate. That invariant makes every terminal lookup a bounded
/// point read: when an older Hold is reached, every possible newer terminal has already been
/// reduced. Missing therefore means in-doubt rather than "not scanned yet".
pub fn drive_gd7_reconciliation_plan_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    effect_proof_ports_chirho: &Gd7EffectProofPortsChirho<'_>,
    observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
    expected_checkpoint_ref_chirho: &str,
) -> Result<Gd7PlanPageDriveOutcomeChirho, Gd7PlanRefusalChirho> {
    if !is_lower_hex_digest_chirho(expected_checkpoint_ref_chirho) {
        return Err(Gd7PlanRefusalChirho::InvalidReferenceChirho);
    }
    let identity_chirho = observation_chirho.identity_chirho();
    let store_chirho = Gd7ReconciliationStoreChirho::new_authenticated_chirho(
        storage_chirho,
        held_signer_chirho,
        identity_chirho.clone(),
        observation_chirho
            .winner_fork_witness_chirho()
            .object_digest_chirho()
            .to_owned(),
    )?;
    let active_chirho = store_chirho
        .load_active_chirho()?
        .ok_or(Gd7PlanRefusalChirho::NoActiveReconciliationChirho)?;
    if active_chirho.checkpoint_ref_chirho != expected_checkpoint_ref_chirho {
        return Err(Gd7PlanRefusalChirho::StaleCheckpointChirho);
    }
    match active_chirho.checkpoint_chirho.state_chirho.phase_chirho {
        Gd7ReconciliationPhaseChirho::ObservedHeldChirho => {
            return Err(Gd7PlanRefusalChirho::InvalidPhaseChirho);
        }
        Gd7ReconciliationPhaseChirho::PlanSealedChirho => {
            validate_sealed_plan_head_chirho(storage_chirho, identity_chirho, &active_chirho)?;
            return Ok(Gd7PlanPageDriveOutcomeChirho::AlreadyAdvancedChirho(
                active_chirho,
            ));
        }
        Gd7ReconciliationPhaseChirho::AdoptedHeldChirho => {
            return Err(Gd7PlanRefusalChirho::InvalidPhaseChirho);
        }
        Gd7ReconciliationPhaseChirho::ManifestingChirho => {}
    }

    let state_chirho = &active_chirho.checkpoint_chirho.state_chirho;
    if state_chirho.plan_page_count_chirho == state_chirho.manifest_page_count_chirho {
        if state_chirho.cursor_object_ref_chirho.is_some() {
            return Ok(Gd7PlanPageDriveOutcomeChirho::AwaitingManifestPageChirho(
                active_chirho,
            ));
        }
        return Err(Gd7PlanRefusalChirho::NoUnreducedManifestPageChirho);
    }
    if state_chirho.plan_page_count_chirho.checked_add(1)
        != Some(state_chirho.manifest_page_count_chirho)
    {
        return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
    }

    let manifest_page_ref_chirho = state_chirho
        .manifest_head_ref_chirho
        .as_deref()
        .ok_or(Gd7PlanRefusalChirho::InvalidPageShapeChirho)?;
    let manifest_page_chirho = load_verified_gd7_losing_manifest_page_chirho(
        storage_chirho,
        manifest_page_ref_chirho,
        identity_chirho,
    )?;
    validate_active_manifest_page_chirho(&manifest_page_chirho, &active_chirho)?;

    let prior_plan_page_chirho = load_prior_plan_page_chirho(
        storage_chirho,
        identity_chirho,
        state_chirho,
        &manifest_page_chirho,
    )?;
    let identity_digest_chirho = gd7_reconciliation_identity_digest_chirho(identity_chirho)?;
    let reduced_chirho = reduce_record_inputs_chirho(
        storage_chirho,
        held_signer_chirho,
        effect_proof_ports_chirho,
        identity_chirho,
        &identity_digest_chirho,
        manifest_page_chirho
            .page_chirho()
            .records_newest_first_chirho()
            .iter()
            .map(|record_chirho| {
                (
                    record_chirho.record_digest_chirho(),
                    record_chirho.record_chirho(),
                )
            }),
    )?;
    let plan_page_chirho = build_plan_page_chirho(
        &identity_digest_chirho,
        &manifest_page_chirho,
        prior_plan_page_chirho.as_ref(),
        reduced_chirho,
    )?;
    if plan_page_chirho.cumulative_manifest_page_count_chirho
        != state_chirho.manifest_page_count_chirho
        || plan_page_chirho.cumulative_manifest_record_count_chirho
            != state_chirho.manifest_record_count_chirho
    {
        return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
    }
    let verified_plan_page_chirho =
        persist_plan_page_chirho(storage_chirho, plan_page_chirho, identity_chirho)?;

    let committed_chirho = store_chirho.commit_plan_checkpoint_chirho(
        expected_checkpoint_ref_chirho,
        &verified_plan_page_chirho,
    )?;
    Ok(Gd7PlanPageDriveOutcomeChirho::CommittedChirho {
        checkpoint_chirho: committed_chirho,
        plan_page_chirho: Box::new(verified_plan_page_chirho),
    })
}

pub(super) fn validate_sealed_plan_head_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    active_chirho: &ActiveGd7ReconciliationChirho,
) -> Result<(), Gd7PlanRefusalChirho> {
    let state_chirho = &active_chirho.checkpoint_chirho.state_chirho;
    let sealed_plan_ref_chirho = state_chirho
        .sealed_plan_ref_chirho
        .as_deref()
        .ok_or(Gd7PlanRefusalChirho::InvalidPageShapeChirho)?;
    let plan_page_chirho = load_verified_gd7_reconciliation_plan_page_chirho(
        storage_chirho,
        sealed_plan_ref_chirho,
        identity_chirho,
    )?;
    if state_chirho.plan_head_ref_chirho.as_deref() != Some(sealed_plan_ref_chirho)
        || state_chirho.manifest_head_ref_chirho.as_deref()
            != Some(
                plan_page_chirho
                    .page_chirho
                    .manifest_page_ref_chirho
                    .as_str(),
            )
        || !plan_page_chirho.page_chirho.reached_anchor_chirho
        || plan_page_chirho
            .page_chirho
            .cumulative_manifest_page_count_chirho
            != state_chirho.manifest_page_count_chirho
        || state_chirho.plan_page_count_chirho != state_chirho.manifest_page_count_chirho
        || plan_page_chirho
            .page_chirho
            .cumulative_manifest_record_count_chirho
            != state_chirho.manifest_record_count_chirho
        || plan_page_chirho
            .page_chirho
            .cumulative_effect_obligation_count_chirho
            != state_chirho.effect_obligation_count_chirho
    {
        return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
    }
    Ok(())
}

/// Verify one content-addressed page's bytes, identity, and internal arithmetic.
///
/// This is not whole-plan semantic authority. Adoption or compensation must additionally verify
/// the linked manifest/plan chain and every referenced effect evidence object.
pub fn load_verified_gd7_reconciliation_plan_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    object_digest_chirho: &str,
    expected_identity_chirho: &Gd7ReconciliationIdentityChirho,
) -> Result<VerifiedGd7ReconciliationPlanPageChirho, Gd7PlanRefusalChirho> {
    if !is_lower_hex_digest_chirho(object_digest_chirho) {
        return Err(Gd7PlanRefusalChirho::InvalidReferenceChirho);
    }
    let path_chirho = gd7_reconciliation_plan_page_path_chirho(object_digest_chirho)?;
    let bytes_chirho = read_bounded_required_chirho(
        storage_chirho,
        &path_chirho,
        MAX_GD7_RECONCILIATION_PLAN_PAGE_BYTES_CHIRHO,
    )?;
    verify_plan_page_bytes_chirho(
        &bytes_chirho,
        object_digest_chirho,
        expected_identity_chirho,
    )
}

fn load_prior_plan_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    state_chirho: &Gd7ReconciliationCheckpointStateChirho,
    manifest_page_chirho: &VerifiedGd7LosingManifestPageChirho,
) -> Result<Option<VerifiedGd7ReconciliationPlanPageChirho>, Gd7PlanRefusalChirho> {
    let Some(prior_plan_ref_chirho) = state_chirho.plan_head_ref_chirho.as_deref() else {
        if state_chirho.plan_page_count_chirho != 0
            || manifest_page_chirho
                .page_chirho()
                .newer_manifest_page_ref_chirho()
                .is_some()
        {
            return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
        }
        return Ok(None);
    };
    let prior_chirho = load_verified_gd7_reconciliation_plan_page_chirho(
        storage_chirho,
        prior_plan_ref_chirho,
        identity_chirho,
    )?;
    if prior_chirho.page_chirho.page_index_chirho.checked_add(1)
        != Some(state_chirho.plan_page_count_chirho)
        || prior_chirho
            .page_chirho
            .cumulative_manifest_page_count_chirho
            != state_chirho.plan_page_count_chirho
        || prior_chirho.page_chirho.reached_anchor_chirho
        || manifest_page_chirho
            .page_chirho()
            .newer_manifest_page_ref_chirho()
            != Some(prior_chirho.page_chirho.manifest_page_ref_chirho.as_str())
    {
        return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
    }
    Ok(Some(prior_chirho))
}

fn validate_active_manifest_page_chirho(
    manifest_page_chirho: &VerifiedGd7LosingManifestPageChirho,
    active_chirho: &ActiveGd7ReconciliationChirho,
) -> Result<(), Gd7PlanRefusalChirho> {
    let state_chirho = &active_chirho.checkpoint_chirho.state_chirho;
    if state_chirho.manifest_head_ref_chirho.as_deref()
        != Some(manifest_page_chirho.object_digest_chirho())
        || manifest_page_chirho
            .page_chirho()
            .page_index_chirho()
            .checked_add(1)
            != Some(state_chirho.manifest_page_count_chirho)
        || manifest_page_chirho
            .page_chirho()
            .next_cursor_object_ref_chirho()
            != state_chirho.cursor_object_ref_chirho.as_deref()
        || manifest_page_chirho.page_chirho().reached_anchor_chirho()
            != state_chirho.cursor_object_ref_chirho.is_none()
    {
        return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
    }
    Ok(())
}

pub(super) fn reduce_record_inputs_chirho<'records_chirho>(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    effect_proof_ports_chirho: &Gd7EffectProofPortsChirho<'_>,
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    identity_digest_chirho: &str,
    records_newest_first_chirho: impl IntoIterator<
        Item = (&'records_chirho str, &'records_chirho LedgerRecordChirho),
    >,
) -> Result<ReducedPlanPageLocalChirho, Gd7PlanRefusalChirho> {
    reduce_record_inputs_with_marker_access_chirho(
        storage_chirho,
        held_signer_chirho,
        effect_proof_ports_chirho,
        identity_chirho,
        identity_digest_chirho,
        records_newest_first_chirho,
        TerminalMarkerAccessChirho::PersistOrLoadChirho {
            signer_chirho: held_signer_chirho,
        },
    )
}

/// VERIFIER ONLY — this is the read-only entry point, and its narrowed port is the whole point.
///
/// A restore path walks this chain. Taking a signer here would mean a caller that provably never
/// signs must hold a signing key to make the call, which is ambient authority conferred by a TYPE
/// rather than by a use. Its sibling [`reduce_record_inputs_chirho`] keeps the signer, and the
/// difference between them is exactly the capability difference between the two modes.
pub(super) fn reverify_record_inputs_read_only_chirho<'records_chirho>(
    storage_chirho: &dyn LedgerStoragePortChirho,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    effect_proof_ports_chirho: &Gd7EffectProofPortsChirho<'_>,
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    identity_digest_chirho: &str,
    records_newest_first_chirho: impl IntoIterator<
        Item = (&'records_chirho str, &'records_chirho LedgerRecordChirho),
    >,
) -> Result<ReducedPlanPageLocalChirho, Gd7PlanRefusalChirho> {
    reduce_record_inputs_with_marker_access_chirho(
        storage_chirho,
        verifier_chirho,
        effect_proof_ports_chirho,
        identity_chirho,
        identity_digest_chirho,
        records_newest_first_chirho,
        TerminalMarkerAccessChirho::LoadRequiredChirho,
    )
}

/// TAKES A VERIFIER, NEVER A SIGNER. Any signing authority arrives inside
/// [`TerminalMarkerAccessChirho::PersistOrLoadChirho`], so the read-only mode has none in scope.
fn reduce_record_inputs_with_marker_access_chirho<'records_chirho>(
    storage_chirho: &dyn LedgerStoragePortChirho,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    effect_proof_ports_chirho: &Gd7EffectProofPortsChirho<'_>,
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    identity_digest_chirho: &str,
    records_newest_first_chirho: impl IntoIterator<
        Item = (&'records_chirho str, &'records_chirho LedgerRecordChirho),
    >,
    marker_access_chirho: TerminalMarkerAccessChirho<'_>,
) -> Result<ReducedPlanPageLocalChirho, Gd7PlanRefusalChirho> {
    let mut reduced_chirho = ReducedPlanPageLocalChirho::default();
    for (record_digest_chirho, record_chirho) in records_newest_first_chirho {
        match classify_effect_record_fact_chirho(record_chirho)? {
            EffectRecordFactChirho::LedgerOnlyChirho => increment_chirho(
                &mut reduced_chirho
                    .fact_counts_chirho
                    .ledger_only_record_count_chirho,
            )?,
            EffectRecordFactChirho::EffectHoldChirho {
                lineage_chirho,
                intent_ref_chirho,
                control_chirho,
            } => {
                increment_chirho(
                    &mut reduced_chirho
                        .fact_counts_chirho
                        .effect_hold_record_count_chirho,
                )?;
                let coordinates_chirho = load_verified_intent_coordinates_chirho(
                    effect_proof_ports_chirho.evidence_chirho,
                    effect_proof_ports_chirho.intent_verifier_chirho,
                    identity_chirho,
                    &intent_ref_chirho,
                )?;
                ensure_hold_binding_chirho(
                    lineage_chirho,
                    record_chirho,
                    &control_chirho,
                    &coordinates_chirho,
                )?;
                // OUTSIDE the access-mode match, so this runs under BOTH modes and must therefore
                // take the narrower port — the read-only mode has no signer to offer it.
                if let Some(marker_chirho) = load_terminal_marker_optional_chirho(
                    storage_chirho,
                    verifier_chirho,
                    identity_digest_chirho,
                    &intent_ref_chirho,
                )? {
                    ensure_marker_resolves_hold_chirho(
                        marker_chirho.marker_chirho(),
                        identity_digest_chirho,
                        &intent_ref_chirho,
                        &control_chirho,
                        &coordinates_chirho,
                        record_chirho.seq_chirho,
                    )?;
                    increment_chirho(
                        &mut reduced_chirho.fact_counts_chirho.resolved_hold_count_chirho,
                    )?;
                } else {
                    increment_chirho(
                        &mut reduced_chirho
                            .fact_counts_chirho
                            .unresolved_hold_count_chirho,
                    )?;
                    reduced_chirho
                        .obligations_newest_first_chirho
                        .push(obligation_chirho(ObligationInputChirho {
                            kind_chirho:
                                Gd7EffectPlanObligationKindChirho::InDoubtHoldOnLosingForkChirho,
                            intent_ref_chirho: &intent_ref_chirho,
                            coordinates_chirho: &coordinates_chirho,
                            control_chirho,
                            outcome_ref_chirho: None,
                            source_record_chirho: record_chirho,
                            source_record_digest_chirho: record_digest_chirho,
                            terminal_marker_object_digest_chirho: None,
                        }));
                }
            }
            EffectRecordFactChirho::EffectTerminalChirho {
                intent_ref_chirho,
                outcome_ref_chirho,
                control_chirho,
                disposition_chirho,
            } => {
                increment_chirho(
                    &mut reduced_chirho
                        .fact_counts_chirho
                        .effect_terminal_record_count_chirho,
                )?;
                let coordinates_chirho = load_verified_intent_coordinates_chirho(
                    effect_proof_ports_chirho.evidence_chirho,
                    effect_proof_ports_chirho.intent_verifier_chirho,
                    identity_chirho,
                    &intent_ref_chirho,
                )?;
                let terminal_disposition_chirho = match disposition_chirho {
                    EffectTerminalFactDispositionChirho::CommittedFinalizeChirho => {
                        Gd7TerminalDispositionChirho::CommittedFinalizeChirho
                    }
                    EffectTerminalFactDispositionChirho::DefiniteNoEffectReleaseChirho => {
                        Gd7TerminalDispositionChirho::DefiniteNoEffectReleaseChirho
                    }
                };
                ensure_terminal_binding_chirho(
                    effect_proof_ports_chirho,
                    TerminalBindingInputChirho {
                        record_chirho,
                        intent_ref_chirho: &intent_ref_chirho,
                        outcome_ref_chirho: &outcome_ref_chirho,
                        control_chirho: &control_chirho,
                        disposition_chirho: terminal_disposition_chirho,
                        coordinates_chirho: &coordinates_chirho,
                    },
                )?;
                let marker_input_chirho = Gd7TerminalMarkerInputChirho {
                    reconciliation_identity_digest_chirho: identity_digest_chirho,
                    intent_ref_chirho: &intent_ref_chirho,
                    lineage_chirho: coordinates_chirho.lineage_chirho,
                    original_effect_key_chirho: coordinates_chirho
                        .warrant_chirho
                        .original_effect_key_chirho
                        .as_deref(),
                    control_chirho: &control_chirho,
                    outcome_ref_chirho: &outcome_ref_chirho,
                    disposition_chirho: terminal_disposition_chirho,
                    terminal_seq_chirho: record_chirho.seq_chirho,
                    terminal_record_digest_chirho: record_digest_chirho,
                };
                let marker_chirho = match marker_access_chirho {
                    // The signer comes out of the VARIANT, not from an ambient parameter — which is
                    // why the arm below has none to reach for.
                    TerminalMarkerAccessChirho::PersistOrLoadChirho { signer_chirho } => {
                        persist_or_load_terminal_marker_chirho(
                            storage_chirho,
                            signer_chirho,
                            marker_input_chirho,
                        )?
                    }
                    TerminalMarkerAccessChirho::LoadRequiredChirho => {
                        load_matching_terminal_marker_required_chirho(
                            storage_chirho,
                            verifier_chirho,
                            marker_input_chirho,
                        )?
                    }
                };
                reduced_chirho
                    .terminal_marker_object_digests_newest_first_chirho
                    .push(marker_chirho.object_digest_chirho().to_owned());
                match terminal_disposition_chirho {
                    Gd7TerminalDispositionChirho::CommittedFinalizeChirho => {
                        increment_chirho(
                            &mut reduced_chirho
                                .fact_counts_chirho
                                .committed_terminal_count_chirho,
                        )?;
                        reduced_chirho
                            .obligations_newest_first_chirho
                            .push(obligation_chirho(ObligationInputChirho {
                                kind_chirho:
                                    Gd7EffectPlanObligationKindChirho::CommittedOnLosingForkChirho,
                                intent_ref_chirho: &intent_ref_chirho,
                                coordinates_chirho: &coordinates_chirho,
                                control_chirho,
                                outcome_ref_chirho: Some(outcome_ref_chirho),
                                source_record_chirho: record_chirho,
                                source_record_digest_chirho: record_digest_chirho,
                                terminal_marker_object_digest_chirho: Some(
                                    marker_chirho.object_digest_chirho().to_owned(),
                                ),
                            }));
                    }
                    Gd7TerminalDispositionChirho::DefiniteNoEffectReleaseChirho => {
                        increment_chirho(
                            &mut reduced_chirho
                                .fact_counts_chirho
                                .definite_no_effect_terminal_count_chirho,
                        )?;
                    }
                }
            }
        }
    }
    Ok(reduced_chirho)
}

fn load_verified_intent_coordinates_chirho(
    effect_evidence_chirho: &dyn Gd7EffectEvidenceReaderPortChirho,
    intent_verifier_chirho: &dyn EffectIntentSignerPortChirho,
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    intent_ref_chirho: &DigestChirho,
) -> Result<VerifiedIntentCoordinatesChirho, Gd7PlanRefusalChirho> {
    let bytes_chirho = effect_evidence_chirho
        .load_intent_line_bounded_chirho(intent_ref_chirho, MAX_GD7_EFFECT_INTENT_LINE_BYTES_CHIRHO)
        .map_err(|_| Gd7PlanRefusalChirho::IntentEvidenceUnavailableChirho)?
        .ok_or(Gd7PlanRefusalChirho::MissingIntentEvidenceChirho)?;
    if bytes_chirho.len() > MAX_GD7_EFFECT_INTENT_LINE_BYTES_CHIRHO {
        return Err(Gd7PlanRefusalChirho::InvalidIntentEvidenceChirho);
    }
    let line_chirho = std::str::from_utf8(&bytes_chirho)
        .map_err(|_| Gd7PlanRefusalChirho::InvalidIntentEvidenceChirho)?;
    // The projection carries the MINIMAL warrant, not the intent line. Same verification SHAPE as
    // before -- canonical bytes, signature, then the ref and genesis equalities -- but the bytes
    // never contain the payer-account owner or the causer principal. See
    // `cairn_effect_commit_chirho::minimal_warrant_chirho` for why the narrowing is equivalent.
    let warrant_chirho = verify_minimal_warrant_line_chirho(line_chirho, intent_verifier_chirho)
        .map_err(|_| Gd7PlanRefusalChirho::InvalidIntentEvidenceChirho)?;
    if warrant_chirho.intent_ref_chirho != *intent_ref_chirho
        || warrant_chirho.journal_genesis_digest_chirho.0
            != identity_chirho.losing_journal_genesis_digest_chirho
    {
        return Err(Gd7PlanRefusalChirho::IntentEvidenceMismatchChirho);
    }
    let original_effect_key_chirho = warrant_chirho.original_effect_key_chirho.clone();
    let (lineage_chirho, expected_control_saga_id_chirho) =
        if let Some(original_effect_key_chirho) = original_effect_key_chirho.as_deref() {
            let compensation_key_chirho =
                effect_compensation_key_chirho(original_effect_key_chirho)
                    .map_err(|_| Gd7PlanRefusalChirho::InvalidIntentEvidenceChirho)?;
            let compensation_control_chirho =
                parse_effect_compensation_key_chirho(&compensation_key_chirho)
                    .map_err(|_| Gd7PlanRefusalChirho::InvalidIntentEvidenceChirho)?;
            (
                Gd7EffectLineageChirho::CompensationChirho,
                compensation_control_chirho,
            )
        } else {
            (
                Gd7EffectLineageChirho::ForwardChirho,
                intent_ref_chirho.clone(),
            )
        };
    Ok(VerifiedIntentCoordinatesChirho {
        lineage_chirho,
        expected_control_saga_id_chirho,
        warrant_chirho,
    })
}

fn ensure_hold_binding_chirho(
    classified_lineage_chirho: EffectHoldLineageChirho,
    record_chirho: &LedgerRecordChirho,
    control_chirho: &EscrowControlChirho,
    coordinates_chirho: &VerifiedIntentCoordinatesChirho,
) -> Result<(), Gd7PlanRefusalChirho> {
    let expected_lineage_chirho = match classified_lineage_chirho {
        EffectHoldLineageChirho::ForwardChirho => Gd7EffectLineageChirho::ForwardChirho,
        EffectHoldLineageChirho::CompensationChirho => Gd7EffectLineageChirho::CompensationChirho,
    };
    if expected_lineage_chirho != coordinates_chirho.lineage_chirho {
        return Err(Gd7PlanRefusalChirho::EffectLineageMismatchChirho);
    }
    let warrant_chirho = &coordinates_chirho.warrant_chirho;
    let predecessor_seq_chirho = record_chirho
        .seq_chirho
        .checked_sub(1)
        .ok_or(Gd7PlanRefusalChirho::IntentEvidenceMismatchChirho)?;
    let [leg_chirho] = record_chirho.legs_chirho.as_slice() else {
        return Err(Gd7PlanRefusalChirho::IntentEvidenceMismatchChirho);
    };
    // The two identifying fields are compared through their BINDINGS, recomputed here from the
    // record's own already-verified values. Equality semantics are identical to comparing the
    // plaintext -- which is all this check ever did -- while the projection carries neither the
    // account owner nor the causer principal.
    if control_chirho.saga_id_chirho != coordinates_chirho.expected_control_saga_id_chirho
        || control_chirho.step_chirho != warrant_chirho.effect_step_chirho
        || record_chirho.attribution_chirho.binding_digest_chirho()
            != warrant_chirho.attribution_binding_chirho
        || warrant_chirho.tail_seq_chirho != predecessor_seq_chirho
        || warrant_chirho.tail_record_digest_chirho != record_chirho.prev_chirho
        || leg_chirho.account_chirho.digest_chirho() != warrant_chirho.payer_account_binding_chirho
        || leg_chirho.kind_policy_ref_chirho != warrant_chirho.kind_policy_ref_chirho
        || leg_chirho.delta_chirho != LegDeltaChirho::HoldChirho
        || leg_chirho.amount_chirho != warrant_chirho.amount_chirho
        || leg_chirho.counterpart_chirho.is_some()
    {
        return Err(Gd7PlanRefusalChirho::IntentEvidenceMismatchChirho);
    }
    Ok(())
}

fn ensure_terminal_binding_chirho(
    effect_proof_ports_chirho: &Gd7EffectProofPortsChirho<'_>,
    input_chirho: TerminalBindingInputChirho<'_>,
) -> Result<(), Gd7PlanRefusalChirho> {
    let bytes_chirho = effect_proof_ports_chirho
        .evidence_chirho
        .load_terminal_line_bounded_chirho(
            input_chirho.outcome_ref_chirho,
            MAX_GD7_EFFECT_TERMINAL_LINE_BYTES_CHIRHO,
        )
        .map_err(|_| Gd7PlanRefusalChirho::TerminalEvidenceUnavailableChirho)?
        .ok_or(Gd7PlanRefusalChirho::MissingTerminalEvidenceChirho)?;
    if bytes_chirho.len() > MAX_GD7_EFFECT_TERMINAL_LINE_BYTES_CHIRHO {
        return Err(Gd7PlanRefusalChirho::InvalidTerminalEvidenceChirho);
    }
    let line_chirho = std::str::from_utf8(&bytes_chirho)
        .map_err(|_| Gd7PlanRefusalChirho::InvalidTerminalEvidenceChirho)?;
    let verified_chirho = verify_effect_terminal_outcome_line_chirho(
        line_chirho,
        effect_proof_ports_chirho.terminal_verifier_chirho,
    )
    .map_err(|_| Gd7PlanRefusalChirho::InvalidTerminalEvidenceChirho)?;
    let signed_disposition_matches_chirho = matches!(
        (
            input_chirho.disposition_chirho,
            &verified_chirho.outcome_chirho().disposition_chirho,
        ),
        (
            Gd7TerminalDispositionChirho::CommittedFinalizeChirho,
            SignedEffectTerminalDispositionChirho::CommittedChirho { .. },
        ) | (
            Gd7TerminalDispositionChirho::DefiniteNoEffectReleaseChirho,
            SignedEffectTerminalDispositionChirho::DefiniteNoEffectChirho,
        )
    );
    let warrant_chirho = &input_chirho.coordinates_chirho.warrant_chirho;
    if verified_chirho.outcome_ref_chirho() != input_chirho.outcome_ref_chirho
        || verified_chirho.outcome_chirho().intent_ref_chirho != *input_chirho.intent_ref_chirho
        || !signed_disposition_matches_chirho
        || input_chirho.control_chirho.saga_id_chirho
            != input_chirho
                .coordinates_chirho
                .expected_control_saga_id_chirho
        || input_chirho.control_chirho.step_chirho != warrant_chirho.effect_step_chirho
        || input_chirho
            .record_chirho
            .attribution_chirho
            .binding_digest_chirho()
            != warrant_chirho.attribution_binding_chirho
        || !terminal_legs_match_warrant_chirho(
            input_chirho.record_chirho,
            input_chirho.disposition_chirho,
            warrant_chirho,
        )
    {
        return Err(Gd7PlanRefusalChirho::TerminalEvidenceMismatchChirho);
    }
    Ok(())
}

/// Terminal leg shape against the warrant. The payer account is matched through its BINDING, the
/// same substitution the hold path makes and for the same reason.
fn terminal_legs_match_warrant_chirho(
    record_chirho: &LedgerRecordChirho,
    disposition_chirho: Gd7TerminalDispositionChirho,
    warrant_chirho: &MinimalEffectWarrantChirho,
) -> bool {
    match disposition_chirho {
        Gd7TerminalDispositionChirho::DefiniteNoEffectReleaseChirho => {
            let [release_chirho] = record_chirho.legs_chirho.as_slice() else {
                return false;
            };
            release_chirho.delta_chirho == LegDeltaChirho::ReleaseChirho
                && release_chirho.account_chirho.digest_chirho()
                    == warrant_chirho.payer_account_binding_chirho
                && release_chirho.account_chirho.kind_id_chirho == warrant_chirho.kind_id_chirho
                && release_chirho.amount_chirho == warrant_chirho.amount_chirho
                && release_chirho.counterpart_chirho.is_none()
        }
        Gd7TerminalDispositionChirho::CommittedFinalizeChirho => {
            let [first_chirho, second_chirho] = record_chirho.legs_chirho.as_slice() else {
                return false;
            };
            let (finalize_chirho, credit_chirho) =
                match (&first_chirho.delta_chirho, &second_chirho.delta_chirho) {
                    (LegDeltaChirho::FinalizeChirho, LegDeltaChirho::CreditChirho) => {
                        (first_chirho, second_chirho)
                    }
                    (LegDeltaChirho::CreditChirho, LegDeltaChirho::FinalizeChirho) => {
                        (second_chirho, first_chirho)
                    }
                    _ => return false,
                };
            finalize_chirho.account_chirho.digest_chirho()
                == warrant_chirho.payer_account_binding_chirho
                && finalize_chirho.account_chirho.kind_id_chirho == warrant_chirho.kind_id_chirho
                && credit_chirho.account_chirho.kind_id_chirho == warrant_chirho.kind_id_chirho
                && finalize_chirho.kind_policy_ref_chirho == credit_chirho.kind_policy_ref_chirho
                && finalize_chirho.amount_chirho == warrant_chirho.amount_chirho
                && credit_chirho.amount_chirho == warrant_chirho.amount_chirho
                && finalize_chirho.counterpart_chirho.is_none()
                && credit_chirho.counterpart_chirho.is_none()
        }
    }
}

fn ensure_marker_resolves_hold_chirho(
    marker_chirho: &super::contract_chirho::Gd7TerminalMarkerChirho,
    identity_digest_chirho: &str,
    intent_ref_chirho: &DigestChirho,
    control_chirho: &EscrowControlChirho,
    coordinates_chirho: &VerifiedIntentCoordinatesChirho,
    hold_seq_chirho: u64,
) -> Result<(), Gd7PlanRefusalChirho> {
    if marker_chirho.reconciliation_identity_digest_chirho != identity_digest_chirho
        || marker_chirho.intent_ref_chirho != *intent_ref_chirho
        || marker_chirho.lineage_chirho != coordinates_chirho.lineage_chirho
        || marker_chirho.original_effect_key_chirho
            != coordinates_chirho.warrant_chirho.original_effect_key_chirho
        || marker_chirho.control_chirho != *control_chirho
        || marker_chirho.terminal_seq_chirho <= hold_seq_chirho
    {
        return Err(Gd7PlanRefusalChirho::TerminalMarkerMismatchChirho);
    }
    Ok(())
}

fn obligation_chirho(input_chirho: ObligationInputChirho<'_>) -> Gd7EffectPlanObligationChirho {
    Gd7EffectPlanObligationChirho {
        kind_chirho: input_chirho.kind_chirho,
        lineage_chirho: input_chirho.coordinates_chirho.lineage_chirho,
        intent_ref_chirho: input_chirho.intent_ref_chirho.clone(),
        original_effect_key_chirho: input_chirho
            .coordinates_chirho
            .warrant_chirho
            .original_effect_key_chirho
            .clone(),
        reversion_contract_digest_chirho: input_chirho
            .coordinates_chirho
            .warrant_chirho
            .reversion_contract_digest_chirho
            .clone(),
        control_chirho: input_chirho.control_chirho,
        outcome_ref_chirho: input_chirho.outcome_ref_chirho,
        source_seq_chirho: input_chirho.source_record_chirho.seq_chirho,
        source_record_digest_chirho: input_chirho.source_record_digest_chirho.to_owned(),
        terminal_marker_object_digest_chirho: input_chirho.terminal_marker_object_digest_chirho,
    }
}

fn build_plan_page_chirho(
    identity_digest_chirho: &str,
    manifest_page_chirho: &VerifiedGd7LosingManifestPageChirho,
    prior_plan_page_chirho: Option<&VerifiedGd7ReconciliationPlanPageChirho>,
    reduced_chirho: ReducedPlanPageLocalChirho,
) -> Result<Gd7ReconciliationPlanPageChirho, Gd7PlanRefusalChirho> {
    let local_record_count_chirho = u64::try_from(
        manifest_page_chirho
            .page_chirho()
            .records_newest_first_chirho()
            .len(),
    )
    .map_err(|_| Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?;
    let local_obligation_count_chirho =
        u64::try_from(reduced_chirho.obligations_newest_first_chirho.len())
            .map_err(|_| Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?;
    let prior_record_count_chirho = prior_plan_page_chirho
        .map(|page_chirho| {
            page_chirho
                .page_chirho
                .cumulative_manifest_record_count_chirho
        })
        .unwrap_or(0);
    let prior_obligation_count_chirho = prior_plan_page_chirho
        .map(|page_chirho| {
            page_chirho
                .page_chirho
                .cumulative_effect_obligation_count_chirho
        })
        .unwrap_or(0);
    let page_chirho = Gd7ReconciliationPlanPageChirho {
        schema_chirho: GD7_RECONCILIATION_PLAN_PAGE_SCHEMA_V1_CHIRHO.to_owned(),
        reconciliation_identity_digest_chirho: identity_digest_chirho.to_owned(),
        page_index_chirho: manifest_page_chirho.page_chirho().page_index_chirho(),
        manifest_page_ref_chirho: manifest_page_chirho.object_digest_chirho().to_owned(),
        newer_plan_page_ref_chirho: prior_plan_page_chirho
            .map(|page_chirho| page_chirho.object_digest_chirho.clone()),
        manifest_record_count_chirho: local_record_count_chirho,
        local_fact_counts_chirho: reduced_chirho.fact_counts_chirho,
        obligations_newest_first_chirho: reduced_chirho.obligations_newest_first_chirho,
        terminal_marker_object_digests_newest_first_chirho: reduced_chirho
            .terminal_marker_object_digests_newest_first_chirho,
        cumulative_manifest_page_count_chirho: manifest_page_chirho
            .page_chirho()
            .page_index_chirho()
            .checked_add(1)
            .ok_or(Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?,
        cumulative_manifest_record_count_chirho: prior_record_count_chirho
            .checked_add(local_record_count_chirho)
            .ok_or(Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?,
        cumulative_effect_obligation_count_chirho: prior_obligation_count_chirho
            .checked_add(local_obligation_count_chirho)
            .ok_or(Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?,
        reached_anchor_chirho: manifest_page_chirho.page_chirho().reached_anchor_chirho(),
    };
    validate_plan_page_chirho(&page_chirho, identity_digest_chirho)?;
    Ok(page_chirho)
}

fn persist_plan_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    page_chirho: Gd7ReconciliationPlanPageChirho,
    identity_chirho: &Gd7ReconciliationIdentityChirho,
) -> Result<VerifiedGd7ReconciliationPlanPageChirho, Gd7PlanRefusalChirho> {
    let bytes_chirho =
        serde_json::to_vec(&page_chirho).map_err(|_| Gd7PlanRefusalChirho::SerializationChirho)?;
    if bytes_chirho.len() > MAX_GD7_RECONCILIATION_PLAN_PAGE_BYTES_CHIRHO {
        return Err(Gd7PlanRefusalChirho::OversizedPlanPageChirho);
    }
    let digest_chirho = digest_bytes_chirho(&bytes_chirho);
    let path_chirho = gd7_reconciliation_plan_page_path_chirho(&digest_chirho)?;
    persist_immutable_chirho(
        storage_chirho,
        &path_chirho,
        &bytes_chirho,
        MAX_GD7_RECONCILIATION_PLAN_PAGE_BYTES_CHIRHO,
    )?;
    verify_plan_page_bytes_chirho(&bytes_chirho, &digest_chirho, identity_chirho)
}

fn verify_plan_page_bytes_chirho(
    bytes_chirho: &[u8],
    expected_object_digest_chirho: &str,
    expected_identity_chirho: &Gd7ReconciliationIdentityChirho,
) -> Result<VerifiedGd7ReconciliationPlanPageChirho, Gd7PlanRefusalChirho> {
    if bytes_chirho.len() > MAX_GD7_RECONCILIATION_PLAN_PAGE_BYTES_CHIRHO {
        return Err(Gd7PlanRefusalChirho::OversizedPlanPageChirho);
    }
    if digest_bytes_chirho(bytes_chirho) != expected_object_digest_chirho {
        return Err(Gd7PlanRefusalChirho::ObjectDigestMismatchChirho);
    }
    let page_chirho: Gd7ReconciliationPlanPageChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_| Gd7PlanRefusalChirho::MalformedPlanPageChirho)?;
    if serde_json::to_vec(&page_chirho).map_err(|_| Gd7PlanRefusalChirho::SerializationChirho)?
        != bytes_chirho
    {
        return Err(Gd7PlanRefusalChirho::NonCanonicalPlanPageChirho);
    }
    let expected_identity_digest_chirho =
        gd7_reconciliation_identity_digest_chirho(expected_identity_chirho)?;
    validate_plan_page_chirho(&page_chirho, &expected_identity_digest_chirho)?;
    Ok(VerifiedGd7ReconciliationPlanPageChirho {
        object_digest_chirho: expected_object_digest_chirho.to_owned(),
        page_chirho,
    })
}

fn validate_plan_page_chirho(
    page_chirho: &Gd7ReconciliationPlanPageChirho,
    expected_identity_digest_chirho: &str,
) -> Result<(), Gd7PlanRefusalChirho> {
    let counts_chirho = &page_chirho.local_fact_counts_chirho;
    let classified_record_count_chirho = counts_chirho
        .ledger_only_record_count_chirho
        .checked_add(counts_chirho.effect_hold_record_count_chirho)
        .and_then(|count_chirho| {
            count_chirho.checked_add(counts_chirho.effect_terminal_record_count_chirho)
        })
        .ok_or(Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?;
    let classified_hold_count_chirho = counts_chirho
        .resolved_hold_count_chirho
        .checked_add(counts_chirho.unresolved_hold_count_chirho)
        .ok_or(Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?;
    let classified_terminal_count_chirho = counts_chirho
        .committed_terminal_count_chirho
        .checked_add(counts_chirho.definite_no_effect_terminal_count_chirho)
        .ok_or(Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?;
    let local_obligation_count_chirho = counts_chirho
        .committed_terminal_count_chirho
        .checked_add(counts_chirho.unresolved_hold_count_chirho)
        .ok_or(Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?;
    if page_chirho.schema_chirho != GD7_RECONCILIATION_PLAN_PAGE_SCHEMA_V1_CHIRHO
        || page_chirho.reconciliation_identity_digest_chirho != expected_identity_digest_chirho
        || !is_lower_hex_digest_chirho(&page_chirho.reconciliation_identity_digest_chirho)
        || !is_lower_hex_digest_chirho(&page_chirho.manifest_page_ref_chirho)
        || (page_chirho.page_index_chirho == 0) != page_chirho.newer_plan_page_ref_chirho.is_none()
        || page_chirho
            .newer_plan_page_ref_chirho
            .as_deref()
            .is_some_and(|reference_chirho| !is_lower_hex_digest_chirho(reference_chirho))
        || page_chirho.cumulative_manifest_page_count_chirho
            != page_chirho
                .page_index_chirho
                .checked_add(1)
                .ok_or(Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?
        || classified_record_count_chirho != page_chirho.manifest_record_count_chirho
        || classified_hold_count_chirho != counts_chirho.effect_hold_record_count_chirho
        || classified_terminal_count_chirho != counts_chirho.effect_terminal_record_count_chirho
        || u64::try_from(page_chirho.obligations_newest_first_chirho.len())
            .map_err(|_| Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?
            != local_obligation_count_chirho
        || u64::try_from(
            page_chirho
                .terminal_marker_object_digests_newest_first_chirho
                .len(),
        )
        .map_err(|_| Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?
            != counts_chirho.effect_terminal_record_count_chirho
        || page_chirho
            .terminal_marker_object_digests_newest_first_chirho
            .iter()
            .any(|digest_chirho| !is_lower_hex_digest_chirho(digest_chirho))
        || page_chirho.cumulative_manifest_record_count_chirho
            < page_chirho.manifest_record_count_chirho
        || page_chirho.cumulative_effect_obligation_count_chirho < local_obligation_count_chirho
    {
        return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
    }
    for obligation_chirho in &page_chirho.obligations_newest_first_chirho {
        let committed_shape_chirho = match obligation_chirho.kind_chirho {
            Gd7EffectPlanObligationKindChirho::CommittedOnLosingForkChirho => {
                obligation_chirho.outcome_ref_chirho.is_some()
                    && obligation_chirho
                        .terminal_marker_object_digest_chirho
                        .is_some()
            }
            Gd7EffectPlanObligationKindChirho::InDoubtHoldOnLosingForkChirho => {
                obligation_chirho.outcome_ref_chirho.is_none()
                    && obligation_chirho
                        .terminal_marker_object_digest_chirho
                        .is_none()
            }
        };
        let lineage_shape_chirho = matches!(
            obligation_chirho.lineage_chirho,
            Gd7EffectLineageChirho::CompensationChirho
        ) == obligation_chirho.original_effect_key_chirho.is_some();
        if !committed_shape_chirho
            || !lineage_shape_chirho
            || !is_lower_hex_digest_chirho(&obligation_chirho.intent_ref_chirho.0)
            || !is_lower_hex_digest_chirho(&obligation_chirho.reversion_contract_digest_chirho.0)
            || !is_lower_hex_digest_chirho(&obligation_chirho.control_chirho.saga_id_chirho.0)
            || !is_lower_hex_digest_chirho(&obligation_chirho.source_record_digest_chirho)
            || obligation_chirho
                .outcome_ref_chirho
                .as_ref()
                .is_some_and(|digest_chirho| !is_lower_hex_digest_chirho(&digest_chirho.0))
            || obligation_chirho
                .terminal_marker_object_digest_chirho
                .as_deref()
                .is_some_and(|digest_chirho| !is_lower_hex_digest_chirho(digest_chirho))
            || obligation_chirho
                .original_effect_key_chirho
                .as_deref()
                .is_some_and(|key_chirho| {
                    !is_bounded_label_chirho(key_chirho, MAX_GD7_RECONCILIATION_LABEL_BYTES_CHIRHO)
                })
        {
            return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
        }
    }
    Ok(())
}

fn increment_chirho(value_chirho: &mut u64) -> Result<(), Gd7PlanRefusalChirho> {
    *value_chirho = value_chirho
        .checked_add(1)
        .ok_or(Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?;
    Ok(())
}
