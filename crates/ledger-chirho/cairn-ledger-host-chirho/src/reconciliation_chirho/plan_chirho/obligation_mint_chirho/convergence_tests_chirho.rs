// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! D1 convergence arms over the genuine two-page chain and real durable R2/R3 rows.
//!
//! The converger enumerates its own population and classifies real state, so no arm here
//! can pass on a caller's assertion about outcomes.

use super::super::authority_chirho::enumerate_gd7_sealed_plan_obligations_chirho;
use super::super::contract_chirho::Gd7ReconciliationPlanPageChirho;
use super::super::tests_chirho::digest_chirho;
use super::gd7_mint_identity_for_verified_obligation_chirho;
use super::tests_chirho::{
    obligation_mint_fixture_chirho, persist_exact_bytes_chirho, persist_plan_checkpoint_chirho,
    ObligationMintFixtureChirho,
};
use crate::reconciliation_chirho::gd7_reconciliation_plan_page_path_chirho;
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;
// `verified_gd7_sealed_plan_obligation_for_test_chirho` moved with the measured-population arm to
// `convergence_import_tests_chirho`; the shared row-driving helpers below are `pub(super)` for it.

use super::super::authority_chirho::{
    classify_gd7_convergence_terminal_outcomes_chirho, release_witness_digest_for_test_chirho,
    sealed_plan_proof_for_convergence_test_chirho, verify_gd7_convergence_chirho,
    Gd7ConvergenceBindingInputChirho, Gd7ConvergenceUnmeasuredPredicatesChirho,
    VerifiedGd7SealedPlanProofChirho,
};
use super::super::conservation_chirho::{
    gd7_conservation_snapshot_signed_content_line_chirho, Gd7ConservationProofPortsChirho,
    Gd7ConservationSnapshotSourcePortChirho, Gd7ConservationSnapshotVerifierPortChirho,
    SignedGd7ConservationSnapshotChirho,
};
use super::super::contract_chirho::Gd7PlanRefusalChirho;
use super::super::obligation_processing_chirho::{
    create_or_load_gd7_obligation_processing_state_chirho,
    dispose_gd7_obligation_held_manual_chirho, mark_gd7_obligation_completed_chirho,
    mark_gd7_obligation_held_manual_chirho, record_gd7_journal_receipt_chirho,
    record_gd7_provider_intent_chirho, record_gd7_provider_observation_chirho,
    Gd7HeldManualDispositionChirho, Gd7ObligationProcessingStateChirho,
    Gd7ObligationTerminalProgressChirho,
};
use super::super::operator_roster_chirho::{
    write_gd7_operator_roster_chirho, Gd7OperatorRosterChirho, Gd7OperatorRosterMemberChirho,
    Gd7OperatorRosterRoleChirho, GD7_OPERATOR_ROSTER_SCHEMA_V1_CHIRHO,
};
use crate::reconciliation_chirho::Gd7ReconciliationSignerPortChirho;
use crate::reconciliation_chirho::{Gd7EffectProofPortsChirho, Gd7ReconciliationCheckpointChirho};
use cairn_ledger_conservation_monitor_chirho::model_chirho::{
    ConservationDomainIdChirho, ConservationHeadCoordinateChirho,
    DomainKindConservationRollupChirho, GlobalKindSupplyChirho,
    HeadConsistentConservationSnapshotChirho,
};
use cairn_ledger_conservation_monitor_chirho::ConservationIncidentKindChirho;
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, DigestChirho};

const CONVERGENCE_JOURNAL_RECEIPT_REF_CHIRHO: &str = "gd7-journal-receipt-chirho";

/// The alternate chain's signed coordinates, as a real mint would have used them.
pub(super) fn alternate_convergence_proof_chirho(
    fixture_chirho: &ObligationMintFixtureChirho,
    effect_obligation_count_chirho: u64,
) -> VerifiedGd7SealedPlanProofChirho {
    sealed_plan_proof_for_convergence_test_chirho(
        fixture_chirho.identity_digest_chirho.clone(),
        fixture_chirho.alternate_checkpoint_ref_chirho.clone(),
        fixture_chirho.alternate_obligation_plan_ref_chirho.clone(),
        fixture_chirho.identity_chirho.winner_term_chirho,
        2,
        2,
        effect_obligation_count_chirho,
    )
}

pub(super) fn convergence_binding_chirho() -> Gd7ConvergenceBindingInputChirho {
    Gd7ConvergenceBindingInputChirho {
        adopted_checkpoint_ref_chirho: digest_chirho('e').0,
    }
}

pub(super) fn satisfied_predicates_chirho() -> Gd7ConvergenceUnmeasuredPredicatesChirho {
    Gd7ConvergenceUnmeasuredPredicatesChirho {
        winner_view_matches_chirho: true,
    }
}

const CONSERVATION_MONEY_GROUP_CHIRHO: &str = "gd7-money-group-chirho";
const CONSERVATION_CLUSTER_CHIRHO: &str = "gd7-cluster-chirho";
const CONSERVATION_KIND_CHIRHO: &str = "gd7-stable-kind-chirho";

/// The conservation snapshot signer's verification root, keyed like the fixture's other fakes.
struct FakeConservationVerifierChirho {
    secret_chirho: [u8; 32],
}

impl FakeConservationVerifierChirho {
    fn signature_chirho(&self, signed_content_chirho: &str) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(&self.secret_chirho);
        hasher_chirho.update(signed_content_chirho.as_bytes());
        hasher_chirho.finalize().to_hex().to_string()
    }
}

impl Gd7ConservationSnapshotVerifierPortChirho for FakeConservationVerifierChirho {
    fn key_id_chirho(&self) -> String {
        blake3::hash(&self.secret_chirho).to_hex().to_string()
    }

    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        self.signature_chirho(canonical_unsigned_chirho) == sig_chirho
    }
}

struct FakeConservationSourceChirho {
    signed_chirho: SignedGd7ConservationSnapshotChirho,
}

impl Gd7ConservationSnapshotSourcePortChirho for FakeConservationSourceChirho {
    fn load_signed_conservation_snapshot_chirho(
        &self,
    ) -> Result<SignedGd7ConservationSnapshotChirho, Gd7PlanRefusalChirho> {
        Ok(self.signed_chirho.clone())
    }
}

fn conservation_verifier_chirho() -> FakeConservationVerifierChirho {
    FakeConservationVerifierChirho {
        secret_chirho: [0x81; 32],
    }
}

/// A snapshot that satisfies every CF4 law: per-rollup `account_net == local_supply`, and the
/// money-group-kind account total equals the independent issuer supply.
fn balanced_conservation_snapshot_chirho() -> HeadConsistentConservationSnapshotChirho {
    let domain_chirho = ConservationDomainIdChirho::new_chirho(
        CONSERVATION_MONEY_GROUP_CHIRHO,
        CONSERVATION_CLUSTER_CHIRHO,
    );
    HeadConsistentConservationSnapshotChirho {
        head_chirho: ConservationHeadCoordinateChirho {
            epoch_chirho: 1,
            checkpoint_digest_chirho: DigestChirho(digest_chirho('a').0),
            covered_record_count_chirho: 2,
        },
        rollups_chirho: vec![DomainKindConservationRollupChirho {
            domain_chirho: domain_chirho.clone(),
            kind_id_chirho: AssetKindIdChirho(CONSERVATION_KIND_CHIRHO.to_owned()),
            account_net_chirho: 1_000,
            local_supply_chirho: 1_000,
        }],
        global_supplies_chirho: vec![GlobalKindSupplyChirho {
            money_group_chirho: domain_chirho.money_group_chirho.clone(),
            kind_id_chirho: AssetKindIdChirho(CONSERVATION_KIND_CHIRHO.to_owned()),
            supply_chirho: 1_000,
        }],
    }
}

/// Sign a snapshot with the LEGITIMATE test key.
///
/// Tamper arms call this AFTER mutating, so their signature verifies honestly and only a
/// conservation law can refuse them. That is the whole point of the money bar here: without the
/// re-sign, every tamper arm would be satisfied by the signature check and prove nothing about
/// whether conservation is measured at all.
fn signed_conservation_snapshot_chirho(
    verifier_chirho: &FakeConservationVerifierChirho,
    snapshot_chirho: HeadConsistentConservationSnapshotChirho,
) -> SignedGd7ConservationSnapshotChirho {
    let content_line_chirho =
        gd7_conservation_snapshot_signed_content_line_chirho(&snapshot_chirho)
            .expect("canonicalize the conservation snapshot");
    SignedGd7ConservationSnapshotChirho {
        key_id_chirho: verifier_chirho.key_id_chirho(),
        sig_chirho: verifier_chirho.signature_chirho(&content_line_chirho),
        snapshot_chirho,
    }
}

fn conservation_source_chirho(
    verifier_chirho: &FakeConservationVerifierChirho,
    snapshot_chirho: HeadConsistentConservationSnapshotChirho,
) -> FakeConservationSourceChirho {
    FakeConservationSourceChirho {
        signed_chirho: signed_conservation_snapshot_chirho(verifier_chirho, snapshot_chirho),
    }
}

/// Enumerate the alternate chain and return its single obligation's mint coordinates.
pub(super) fn alternate_population_mint_identity_chirho(
    fixture_chirho: &ObligationMintFixtureChirho,
) -> (String, String) {
    let effect_ports_chirho = fixture_chirho.effect_ports_chirho();
    let population_chirho = enumerate_gd7_sealed_plan_obligations_chirho(
        &fixture_chirho.storage_chirho,
        &fixture_chirho.held_signer_chirho,
        &fixture_chirho.losing_record_verifier_chirho,
        &effect_ports_chirho,
        &fixture_chirho.alternate_checkpoint_chirho,
    )
    .expect("walk the complete two-page manifest chain");
    assert_eq!(population_chirho.len(), 1);
    gd7_mint_identity_for_verified_obligation_chirho(
        &digest_chirho('e').0,
        &fixture_chirho.alternate_checkpoint_ref_chirho,
        &fixture_chirho.alternate_obligation_plan_ref_chirho,
        &fixture_chirho.identity_digest_chirho,
        fixture_chirho.identity_chirho.winner_term_chirho,
        &population_chirho[0],
    )
    .expect("derive the population obligation's mint identity")
}

/// Create the durable row for the alternate chain's obligation, at AwaitingProviderChirho.
pub(super) fn create_convergence_row_chirho(
    fixture_chirho: &ObligationMintFixtureChirho,
    mint_identity_digest_chirho: &str,
    canonical_obligation_digest_chirho: &str,
) -> Gd7ObligationProcessingStateChirho {
    create_or_load_gd7_obligation_processing_state_chirho(
        &fixture_chirho.storage_chirho,
        mint_identity_digest_chirho,
        "gd7-obligation-receipt-chirho",
        canonical_obligation_digest_chirho,
        "gd7-inverse-authority-chirho",
        "gd7-action-idempotency-chirho",
    )
    .expect("create the durable processing row")
}

/// Drive a row to CompletedChirho through every real transition.
pub(super) fn drive_row_to_completed_chirho(
    fixture_chirho: &ObligationMintFixtureChirho,
    state_chirho: &Gd7ObligationProcessingStateChirho,
) -> Gd7ObligationProcessingStateChirho {
    let intent_chirho = record_gd7_provider_intent_chirho(
        &fixture_chirho.storage_chirho,
        state_chirho,
        "gd7-provider-idempotency-chirho",
        &digest_chirho('7').0,
    )
    .expect("persist the provider intent");
    let observed_chirho = record_gd7_provider_observation_chirho(
        &fixture_chirho.storage_chirho,
        &intent_chirho,
        "gd7-provider-observation-chirho",
        "gd7-provider-effect-id-chirho",
    )
    .expect("record the provider observation");
    let journalled_chirho = record_gd7_journal_receipt_chirho(
        &fixture_chirho.storage_chirho,
        &observed_chirho,
        CONVERGENCE_JOURNAL_RECEIPT_REF_CHIRHO,
    )
    .expect("record the journal receipt");
    mark_gd7_obligation_completed_chirho(&fixture_chirho.storage_chirho, &journalled_chirho)
        .expect("mark the obligation completed")
}

/// Run the converger over an explicit checkpoint and an explicit conservation snapshot.
///
/// The snapshot is always signed with the legitimate key, so a tampered snapshot passed here still
/// authenticates and only a conservation law can refuse it.
#[allow(
    clippy::too_many_arguments,
    reason = "the arms name every injected port explicitly rather than sharing a mutable fixture"
)]
fn run_convergence_at_chirho(
    fixture_chirho: &ObligationMintFixtureChirho,
    plan_checkpoint_chirho: &Gd7ReconciliationCheckpointChirho,
    proof_chirho: &VerifiedGd7SealedPlanProofChirho,
    binding_chirho: Gd7ConvergenceBindingInputChirho,
    predicates_chirho: Gd7ConvergenceUnmeasuredPredicatesChirho,
    snapshot_chirho: HeadConsistentConservationSnapshotChirho,
    effect_ports_chirho: &Gd7EffectProofPortsChirho<'_>,
) -> Result<crate::reconciliation_chirho::ConvergedReadReplicaChirho, Gd7PlanRefusalChirho> {
    let verifier_chirho = conservation_verifier_chirho();
    let source_chirho = conservation_source_chirho(&verifier_chirho, snapshot_chirho);
    run_convergence_with_effect_ports_chirho(
        fixture_chirho,
        plan_checkpoint_chirho,
        proof_chirho,
        binding_chirho,
        predicates_chirho,
        &Gd7ConservationProofPortsChirho::new_chirho(&source_chirho, &verifier_chirho),
        effect_ports_chirho,
    )
}

fn run_convergence_with_ports_chirho(
    fixture_chirho: &ObligationMintFixtureChirho,
    plan_checkpoint_chirho: &Gd7ReconciliationCheckpointChirho,
    proof_chirho: &VerifiedGd7SealedPlanProofChirho,
    binding_chirho: Gd7ConvergenceBindingInputChirho,
    predicates_chirho: Gd7ConvergenceUnmeasuredPredicatesChirho,
    conservation_ports_chirho: &Gd7ConservationProofPortsChirho<'_>,
) -> Result<crate::reconciliation_chirho::ConvergedReadReplicaChirho, Gd7PlanRefusalChirho> {
    run_convergence_with_effect_ports_chirho(
        fixture_chirho,
        plan_checkpoint_chirho,
        proof_chirho,
        binding_chirho,
        predicates_chirho,
        conservation_ports_chirho,
        &fixture_chirho.effect_ports_chirho(),
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the arms name every injected port explicitly rather than sharing a mutable fixture"
)]
fn run_convergence_with_effect_ports_chirho(
    fixture_chirho: &ObligationMintFixtureChirho,
    plan_checkpoint_chirho: &Gd7ReconciliationCheckpointChirho,
    proof_chirho: &VerifiedGd7SealedPlanProofChirho,
    binding_chirho: Gd7ConvergenceBindingInputChirho,
    predicates_chirho: Gd7ConvergenceUnmeasuredPredicatesChirho,
    conservation_ports_chirho: &Gd7ConservationProofPortsChirho<'_>,
    effect_ports_chirho: &Gd7EffectProofPortsChirho<'_>,
) -> Result<crate::reconciliation_chirho::ConvergedReadReplicaChirho, Gd7PlanRefusalChirho> {
    verify_gd7_convergence_chirho(
        &fixture_chirho.storage_chirho,
        &fixture_chirho.held_signer_chirho,
        &fixture_chirho.losing_record_verifier_chirho,
        effect_ports_chirho,
        conservation_ports_chirho,
        plan_checkpoint_chirho,
        proof_chirho,
        binding_chirho,
        predicates_chirho,
    )
}

/// The default arm: the alternate two-page chain with a conserving snapshot.
pub(super) fn run_convergence_chirho(
    fixture_chirho: &ObligationMintFixtureChirho,
    proof_chirho: &VerifiedGd7SealedPlanProofChirho,
    binding_chirho: Gd7ConvergenceBindingInputChirho,
    predicates_chirho: Gd7ConvergenceUnmeasuredPredicatesChirho,
) -> Result<crate::reconciliation_chirho::ConvergedReadReplicaChirho, Gd7PlanRefusalChirho> {
    run_convergence_at_chirho(
        fixture_chirho,
        &fixture_chirho.alternate_checkpoint_chirho,
        proof_chirho,
        binding_chirho,
        predicates_chirho,
        balanced_conservation_snapshot_chirho(),
        &fixture_chirho.effect_ports_chirho(),
    )
}

#[test]
fn convergence_certifies_only_after_the_real_row_reaches_completed_chirho() {
    let fixture_chirho = obligation_mint_fixture_chirho("convergence-completed");
    let (mint_identity_digest_chirho, canonical_obligation_digest_chirho) =
        alternate_population_mint_identity_chirho(&fixture_chirho);
    let proof_chirho = alternate_convergence_proof_chirho(&fixture_chirho, 1);

    // No row at all: the obligation the plan names has not started, which is OPEN.
    assert_eq!(
        run_convergence_chirho(
            &fixture_chirho,
            &proof_chirho,
            convergence_binding_chirho(),
            satisfied_predicates_chirho(),
        ),
        Err(Gd7PlanRefusalChirho::UnconvergedObligationChirho(
            mint_identity_digest_chirho.clone()
        )),
        "an obligation with no durable row must block convergence and name itself"
    );

    let state_chirho = create_convergence_row_chirho(
        &fixture_chirho,
        &mint_identity_digest_chirho,
        &canonical_obligation_digest_chirho,
    );
    let completed_chirho = drive_row_to_completed_chirho(&fixture_chirho, &state_chirho);
    assert_eq!(
        completed_chirho.terminal_progress_chirho(),
        Gd7ObligationTerminalProgressChirho::CompletedChirho
    );

    let certificate_chirho = run_convergence_chirho(
        &fixture_chirho,
        &proof_chirho,
        convergence_binding_chirho(),
        satisfied_predicates_chirho(),
    )
    .expect("a completed population certifies");
    assert_eq!(certificate_chirho.population_count_chirho(), 1);
    assert_eq!(
        certificate_chirho.schema_chirho(),
        crate::reconciliation_chirho::GD7_CONVERGED_READ_REPLICA_SCHEMA_V2_CHIRHO,
        "schema pin: a NEWER left value is the next intended bump — retarget this pin; \
         a v1 left value means v2 emission regressed and THAT is the defect"
    );
    // The D3 release witness stays derivable from the certificate this brick issues.
    assert_eq!(
        release_witness_digest_for_test_chirho(&certificate_chirho).len(),
        64
    );
    fixture_chirho.assert_source_objects_unchanged_chirho();
}

fn dispose_convergence_row_chirho(
    fixture_chirho: &ObligationMintFixtureChirho,
    state_chirho: &Gd7ObligationProcessingStateChirho,
) -> Gd7ObligationProcessingStateChirho {
    let mut disposition_chirho = Gd7HeldManualDispositionChirho::new_chirho(
        state_chirho.mint_identity_digest_chirho().to_owned(),
        fixture_chirho.held_signer_chirho.key_id_chirho.clone(),
        7,
        Some("gd7-compensating-effect-ref-chirho".to_owned()),
        None,
        String::new(),
    );
    let unsigned_bytes_chirho = disposition_chirho
        .canonical_unsigned_bytes_chirho()
        .unwrap();
    disposition_chirho = disposition_chirho.with_signature_chirho(
        fixture_chirho
            .held_signer_chirho
            .sign_chirho(std::str::from_utf8(&unsigned_bytes_chirho).unwrap())
            .unwrap(),
    );
    dispose_gd7_obligation_held_manual_chirho(
        &fixture_chirho.storage_chirho,
        state_chirho,
        disposition_chirho,
        &fixture_chirho.held_signer_chirho,
    )
    .expect("dispose the held row through the signed path")
}

fn write_disposition_roster_chirho(
    fixture_chirho: &ObligationMintFixtureChirho,
    epoch_chirho: u64,
    operator_key_id_chirho: &str,
) {
    let group_chirho = &fixture_chirho
        .alternate_checkpoint_chirho
        .identity_chirho
        .consistency_group_digest_chirho;
    write_gd7_operator_roster_chirho(
        &fixture_chirho.storage_chirho,
        group_chirho,
        &fixture_chirho.held_signer_chirho,
        Gd7OperatorRosterChirho {
            schema_chirho: GD7_OPERATOR_ROSTER_SCHEMA_V1_CHIRHO.to_owned(),
            consistency_group_digest_chirho: group_chirho.clone(),
            roster_epoch_chirho: epoch_chirho,
            signer_key_id_chirho: fixture_chirho.held_signer_chirho.key_id_chirho.clone(),
            members_chirho: vec![Gd7OperatorRosterMemberChirho {
                operator_key_id_chirho: operator_key_id_chirho.to_owned(),
                role_chirho: Gd7OperatorRosterRoleChirho::Gd7DispositionChirho,
            }],
            sig_chirho: String::new(),
        },
    )
    .expect("write the signed operator roster");
}

#[test]
fn convergence_certifies_disposed_without_laundering_completed_count_chirho() {
    let fixture_chirho = obligation_mint_fixture_chirho("convergence-disposed-a11");
    let (mint_identity_digest_chirho, canonical_obligation_digest_chirho) =
        alternate_population_mint_identity_chirho(&fixture_chirho);
    let state_chirho = create_convergence_row_chirho(
        &fixture_chirho,
        &mint_identity_digest_chirho,
        &canonical_obligation_digest_chirho,
    );
    let held_chirho =
        mark_gd7_obligation_held_manual_chirho(&fixture_chirho.storage_chirho, &state_chirho)
            .unwrap();
    let disposed_chirho = dispose_convergence_row_chirho(&fixture_chirho, &held_chirho);
    assert_eq!(disposed_chirho.held_manual_classification_chirho(), Some(super::super::obligation_processing_chirho::Gd7HeldManualClassificationChirho::HeldManualDisposedChirho));
    write_disposition_roster_chirho(
        &fixture_chirho,
        1,
        &fixture_chirho.held_signer_chirho.key_id_chirho,
    );
    let certificate_chirho = run_convergence_chirho(
        &fixture_chirho,
        &alternate_convergence_proof_chirho(&fixture_chirho, 1),
        convergence_binding_chirho(),
        satisfied_predicates_chirho(),
    )
    .unwrap();
    assert_eq!(
        certificate_chirho.verified_v2_counts_chirho().unwrap(),
        (0, 1)
    );
}

#[test]
fn convergence_rechecks_roster_after_operator_rotation_chirho() {
    let fixture_chirho = obligation_mint_fixture_chirho("convergence-disposed-rotation");
    let (mint_identity_digest_chirho, canonical_obligation_digest_chirho) =
        alternate_population_mint_identity_chirho(&fixture_chirho);
    let state_chirho = create_convergence_row_chirho(
        &fixture_chirho,
        &mint_identity_digest_chirho,
        &canonical_obligation_digest_chirho,
    );
    let held_chirho =
        mark_gd7_obligation_held_manual_chirho(&fixture_chirho.storage_chirho, &state_chirho)
            .unwrap();
    dispose_convergence_row_chirho(&fixture_chirho, &held_chirho);
    let held_key_chirho = fixture_chirho.held_signer_chirho.key_id_chirho.clone();
    write_disposition_roster_chirho(&fixture_chirho, 1, &held_key_chirho);
    run_convergence_chirho(
        &fixture_chirho,
        &alternate_convergence_proof_chirho(&fixture_chirho, 1),
        convergence_binding_chirho(),
        satisfied_predicates_chirho(),
    )
    .unwrap();
    write_disposition_roster_chirho(&fixture_chirho, 2, &"c".repeat(64));
    assert!(matches!(
        run_convergence_chirho(
            &fixture_chirho,
            &alternate_convergence_proof_chirho(&fixture_chirho, 1),
            convergence_binding_chirho(),
            satisfied_predicates_chirho()
        ),
        Err(Gd7PlanRefusalChirho::OperatorRosterRefusalChirho(_))
    ));
}

#[test]
fn convergence_refuses_every_nonterminal_progress_including_held_manual_chirho() {
    // Each intermediate progress is driven on its own fixture so no arm inherits another's row.
    // HeldManualChirho is included deliberately: it is OPEN, never a satisfying terminal outcome.
    for (label_chirho, stop_after_chirho) in [
        (
            "awaiting",
            Gd7ObligationTerminalProgressChirho::AwaitingProviderChirho,
        ),
        (
            "intent",
            Gd7ObligationTerminalProgressChirho::ProviderIntentPersistedChirho,
        ),
        (
            "observed",
            Gd7ObligationTerminalProgressChirho::ProviderObservedChirho,
        ),
        (
            "journalled",
            Gd7ObligationTerminalProgressChirho::JournalRecordedChirho,
        ),
        (
            "held-manual",
            Gd7ObligationTerminalProgressChirho::HeldManualChirho,
        ),
    ] {
        let fixture_chirho = obligation_mint_fixture_chirho(&format!("convergence-{label_chirho}"));
        let (mint_identity_digest_chirho, canonical_obligation_digest_chirho) =
            alternate_population_mint_identity_chirho(&fixture_chirho);
        let mut state_chirho = create_convergence_row_chirho(
            &fixture_chirho,
            &mint_identity_digest_chirho,
            &canonical_obligation_digest_chirho,
        );
        if stop_after_chirho != Gd7ObligationTerminalProgressChirho::AwaitingProviderChirho {
            state_chirho = record_gd7_provider_intent_chirho(
                &fixture_chirho.storage_chirho,
                &state_chirho,
                "gd7-provider-idempotency-chirho",
                &digest_chirho('7').0,
            )
            .expect("persist the provider intent");
        }
        if matches!(
            stop_after_chirho,
            Gd7ObligationTerminalProgressChirho::ProviderObservedChirho
                | Gd7ObligationTerminalProgressChirho::JournalRecordedChirho
        ) {
            state_chirho = record_gd7_provider_observation_chirho(
                &fixture_chirho.storage_chirho,
                &state_chirho,
                "gd7-provider-observation-chirho",
                "gd7-provider-effect-id-chirho",
            )
            .expect("record the provider observation");
        }
        if stop_after_chirho == Gd7ObligationTerminalProgressChirho::JournalRecordedChirho {
            state_chirho = record_gd7_journal_receipt_chirho(
                &fixture_chirho.storage_chirho,
                &state_chirho,
                CONVERGENCE_JOURNAL_RECEIPT_REF_CHIRHO,
            )
            .expect("record the journal receipt");
        }
        if stop_after_chirho == Gd7ObligationTerminalProgressChirho::HeldManualChirho {
            state_chirho = mark_gd7_obligation_held_manual_chirho(
                &fixture_chirho.storage_chirho,
                &state_chirho,
            )
            .expect("hold the obligation for an operator");
        }
        assert_eq!(
            state_chirho.terminal_progress_chirho(),
            stop_after_chirho,
            "{label_chirho}: the fixture must actually reach the progress under test"
        );

        let proof_chirho = alternate_convergence_proof_chirho(&fixture_chirho, 1);
        assert_eq!(
            run_convergence_chirho(
                &fixture_chirho,
                &proof_chirho,
                convergence_binding_chirho(),
                satisfied_predicates_chirho(),
            ),
            Err(Gd7PlanRefusalChirho::UnconvergedObligationChirho(
                mint_identity_digest_chirho
            )),
            "{label_chirho}: a non-completed row must block convergence and name the obligation"
        );
    }
}

#[test]
fn convergence_refuses_a_row_describing_a_different_obligation_chirho() {
    let fixture_chirho = obligation_mint_fixture_chirho("convergence-foreign-subject");
    let (mint_identity_digest_chirho, _canonical_obligation_digest_chirho) =
        alternate_population_mint_identity_chirho(&fixture_chirho);
    // A row filed under this obligation's mint identity but describing another obligation.
    let foreign_state_chirho = create_convergence_row_chirho(
        &fixture_chirho,
        &mint_identity_digest_chirho,
        &digest_chirho('9').0,
    );
    let completed_chirho = drive_row_to_completed_chirho(&fixture_chirho, &foreign_state_chirho);
    assert_eq!(
        completed_chirho.terminal_progress_chirho(),
        Gd7ObligationTerminalProgressChirho::CompletedChirho,
        "the foreign row must be COMPLETED, so only the subject binding can refuse it"
    );

    let proof_chirho = alternate_convergence_proof_chirho(&fixture_chirho, 1);
    assert_eq!(
        run_convergence_chirho(
            &fixture_chirho,
            &proof_chirho,
            convergence_binding_chirho(),
            satisfied_predicates_chirho(),
        ),
        Err(Gd7PlanRefusalChirho::ObligationStateSubjectMismatchChirho(
            mint_identity_digest_chirho
        )),
        "a completed row describing a different obligation must refuse by subject, not certify"
    );
}

#[test]
fn convergence_refuses_population_count_mismatch_against_the_signed_proof_chirho() {
    let fixture_chirho = obligation_mint_fixture_chirho("convergence-count-crosscheck");
    let (mint_identity_digest_chirho, canonical_obligation_digest_chirho) =
        alternate_population_mint_identity_chirho(&fixture_chirho);
    let state_chirho = create_convergence_row_chirho(
        &fixture_chirho,
        &mint_identity_digest_chirho,
        &canonical_obligation_digest_chirho,
    );
    drive_row_to_completed_chirho(&fixture_chirho, &state_chirho);

    // The walk finds one obligation; the signed proof says two. The certificate binds the signed
    // count, so a walk that certified a subset must refuse rather than bind its own tally.
    let mismatched_proof_chirho = alternate_convergence_proof_chirho(&fixture_chirho, 2);
    assert_eq!(
        run_convergence_chirho(
            &fixture_chirho,
            &mismatched_proof_chirho,
            convergence_binding_chirho(),
            satisfied_predicates_chirho(),
        ),
        Err(Gd7PlanRefusalChirho::ObligationNotInSealedPlanChirho),
        "a measured population that disagrees with the signed count must refuse"
    );
}

#[test]
fn convergence_refuses_tampered_bindings_and_unsatisfied_predicates_chirho() {
    let fixture_chirho = obligation_mint_fixture_chirho("convergence-tamper");
    let (mint_identity_digest_chirho, canonical_obligation_digest_chirho) =
        alternate_population_mint_identity_chirho(&fixture_chirho);
    let state_chirho = create_convergence_row_chirho(
        &fixture_chirho,
        &mint_identity_digest_chirho,
        &canonical_obligation_digest_chirho,
    );
    drive_row_to_completed_chirho(&fixture_chirho, &state_chirho);
    let proof_chirho = alternate_convergence_proof_chirho(&fixture_chirho, 1);

    // Control: this exact configuration certifies, so every refusal below is caused by its own
    // mutation rather than by a fixture that could never have converged.
    run_convergence_chirho(
        &fixture_chirho,
        &proof_chirho,
        convergence_binding_chirho(),
        satisfied_predicates_chirho(),
    )
    .expect("control: the untampered configuration certifies");

    // The `losing_population_*` and `retained_refs` tamper arms that lived here are gone by
    // construction: those fields left `Gd7ConvergenceBindingInputChirho` — the converger MEASURES the
    // population digests and BINDS the retained refs, so a caller can no longer supply them to tamper.
    // The sibling `convergence_import_tests_chirho` proves the certificate now carries the measured
    // values instead (`convergence_certificate_binds_measured_losing_population_not_a_caller_literal_chirho`).

    let mut tampered_adopted_chirho = convergence_binding_chirho();
    tampered_adopted_chirho.adopted_checkpoint_ref_chirho = "not-a-digest".to_owned();
    assert_eq!(
        run_convergence_chirho(
            &fixture_chirho,
            &proof_chirho,
            tampered_adopted_chirho,
            satisfied_predicates_chirho(),
        ),
        Err(Gd7PlanRefusalChirho::InvalidReferenceChirho)
    );

    // A well-formed but WRONG adopted checkpoint derives mint identities that match no row, so the
    // population classifies OPEN. A bad coordinate can block convergence, never manufacture one.
    let mut foreign_adopted_chirho = convergence_binding_chirho();
    foreign_adopted_chirho.adopted_checkpoint_ref_chirho = digest_chirho('b').0;
    assert!(matches!(
        run_convergence_chirho(
            &fixture_chirho,
            &proof_chirho,
            foreign_adopted_chirho,
            satisfied_predicates_chirho(),
        ),
        Err(Gd7PlanRefusalChirho::UnconvergedObligationChirho(_))
    ));

    // Only the winner-view predicate is still a caller assertion; conservation left this struct and
    // is measured by its own arms below.
    assert_eq!(
        run_convergence_chirho(
            &fixture_chirho,
            &proof_chirho,
            convergence_binding_chirho(),
            Gd7ConvergenceUnmeasuredPredicatesChirho {
                winner_view_matches_chirho: false,
            },
        ),
        Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho)
    );
}

#[test]
fn convergence_certifies_a_measured_zero_obligation_population_chirho() {
    // The enumerator refuses page_count == 0, so the honest empty case is a REAL walked page whose
    // cumulative obligation count is 0. This proves a converged reconciliation that owed nothing
    // certifies, and that the certificate binds the measured zero rather than skipping the walk.
    let fixture_chirho = obligation_mint_fixture_chirho("convergence-zero-obligation");
    let proof_chirho = sealed_plan_proof_for_convergence_test_chirho(
        fixture_chirho.empty_identity_digest_chirho.clone(),
        fixture_chirho.empty_checkpoint_ref_chirho.clone(),
        fixture_chirho.empty_plan_ref_chirho.clone(),
        fixture_chirho.identity_chirho.winner_term_chirho,
        1,
        1,
        0,
    );

    // The population really is empty, measured through the same enumerator the converger uses.
    let effect_ports_chirho = fixture_chirho.effect_ports_chirho();
    let population_chirho = enumerate_gd7_sealed_plan_obligations_chirho(
        &fixture_chirho.storage_chirho,
        &fixture_chirho.held_signer_chirho,
        &fixture_chirho.losing_record_verifier_chirho,
        &effect_ports_chirho,
        &fixture_chirho.empty_checkpoint_chirho,
    )
    .expect("walk the complete one-page zero-obligation chain");
    assert!(
        population_chirho.is_empty(),
        "the zero-obligation chain must enumerate no obligations"
    );

    let certificate_chirho = run_convergence_at_chirho(
        &fixture_chirho,
        &fixture_chirho.empty_checkpoint_chirho,
        &proof_chirho,
        convergence_binding_chirho(),
        satisfied_predicates_chirho(),
        balanced_conservation_snapshot_chirho(),
        &fixture_chirho.effect_ports_chirho(),
    )
    .expect("a converged reconciliation that owed nothing certifies");
    assert_eq!(
        certificate_chirho.population_count_chirho(),
        0,
        "the certificate must bind the measured zero obligation count"
    );

    // A zero here is a MEASURED zero: the same fixture's non-empty chain certifies a different
    // count, so this arm cannot be satisfied by a walk that examined nothing.
    let populated_proof_chirho = alternate_convergence_proof_chirho(&fixture_chirho, 1);
    let (mint_identity_digest_chirho, canonical_obligation_digest_chirho) =
        alternate_population_mint_identity_chirho(&fixture_chirho);
    let state_chirho = create_convergence_row_chirho(
        &fixture_chirho,
        &mint_identity_digest_chirho,
        &canonical_obligation_digest_chirho,
    );
    drive_row_to_completed_chirho(&fixture_chirho, &state_chirho);
    let populated_certificate_chirho = run_convergence_chirho(
        &fixture_chirho,
        &populated_proof_chirho,
        convergence_binding_chirho(),
        satisfied_predicates_chirho(),
    )
    .expect("the same fixture's populated chain certifies");
    assert_eq!(populated_certificate_chirho.population_count_chirho(), 1);
    fixture_chirho.assert_source_objects_unchanged_chirho();
}

#[test]
fn conservation_content_line_is_byte_identical_across_row_orders_chirho() {
    // A6. The rollups and supplies are SETS; their vector order is an artifact of whichever adapter
    // built them, and the CF4 checker reads them order-independently. So two adapters that agree
    // about the money must produce the SAME signed bytes — otherwise the same money state yields
    // two different certificate digests, and a signature made by one adapter fails against the
    // other's ordering for no semantic reason.
    let domain_chirho = ConservationDomainIdChirho::new_chirho(
        CONSERVATION_MONEY_GROUP_CHIRHO,
        CONSERVATION_CLUSTER_CHIRHO,
    );
    let second_kind_chirho = AssetKindIdChirho("gd7-second-kind-chirho".to_owned());
    let rollup_one_chirho = DomainKindConservationRollupChirho {
        domain_chirho: domain_chirho.clone(),
        kind_id_chirho: AssetKindIdChirho(CONSERVATION_KIND_CHIRHO.to_owned()),
        account_net_chirho: 1_000,
        local_supply_chirho: 1_000,
    };
    let rollup_two_chirho = DomainKindConservationRollupChirho {
        domain_chirho: domain_chirho.clone(),
        kind_id_chirho: second_kind_chirho.clone(),
        account_net_chirho: 25,
        local_supply_chirho: 25,
    };
    let supply_one_chirho = GlobalKindSupplyChirho {
        money_group_chirho: domain_chirho.money_group_chirho.clone(),
        kind_id_chirho: AssetKindIdChirho(CONSERVATION_KIND_CHIRHO.to_owned()),
        supply_chirho: 1_000,
    };
    let supply_two_chirho = GlobalKindSupplyChirho {
        money_group_chirho: domain_chirho.money_group_chirho.clone(),
        kind_id_chirho: second_kind_chirho,
        supply_chirho: 25,
    };
    let head_chirho = ConservationHeadCoordinateChirho {
        epoch_chirho: 1,
        checkpoint_digest_chirho: DigestChirho(digest_chirho('a').0),
        covered_record_count_chirho: 2,
    };
    let forward_chirho = HeadConsistentConservationSnapshotChirho {
        head_chirho: head_chirho.clone(),
        rollups_chirho: vec![rollup_one_chirho.clone(), rollup_two_chirho.clone()],
        global_supplies_chirho: vec![supply_one_chirho.clone(), supply_two_chirho.clone()],
    };
    let reversed_chirho = HeadConsistentConservationSnapshotChirho {
        head_chirho,
        rollups_chirho: vec![rollup_two_chirho, rollup_one_chirho],
        global_supplies_chirho: vec![supply_two_chirho, supply_one_chirho],
    };
    // Non-vacuity: the two inputs really are differently ordered, so a passing assertion below is
    // about canonicalization rather than about two identical values.
    assert_ne!(
        forward_chirho, reversed_chirho,
        "the two snapshots must differ in row ORDER, or this arm proves nothing"
    );

    let forward_line_chirho = gd7_conservation_snapshot_signed_content_line_chirho(&forward_chirho)
        .expect("canonicalize the forward-ordered snapshot");
    let reversed_line_chirho =
        gd7_conservation_snapshot_signed_content_line_chirho(&reversed_chirho)
            .expect("canonicalize the reverse-ordered snapshot");
    assert_eq!(
        forward_line_chirho, reversed_line_chirho,
        "semantically identical snapshots must canonicalize to identical BYTES"
    );

    // And the signature made over one ordering verifies against the other, which is the property
    // an adapter actually depends on.
    let verifier_chirho = conservation_verifier_chirho();
    let signed_forward_chirho =
        signed_conservation_snapshot_chirho(&verifier_chirho, forward_chirho);
    assert!(
        verifier_chirho.verify_chirho(&reversed_line_chirho, &signed_forward_chirho.sig_chirho),
        "a signature over one row order must verify against the other"
    );
}

#[test]
fn convergence_discovers_an_obligation_only_on_the_non_entry_page_chirho() {
    // A8, the subset trap. The walk enters at the highest page index; this chain's sole obligation
    // is on page 0, reached SECOND. A converger that stopped at its entry page would measure a
    // population of ZERO and certify — releasing past an obligation it never saw. The zero-obligation
    // arm proves a measured zero; this proves the zero is not produced by a short walk.
    let fixture_chirho = obligation_mint_fixture_chirho("convergence-subset-trap");
    let subset_ports_chirho = fixture_chirho.subset_effect_ports_chirho();
    let population_chirho = enumerate_gd7_sealed_plan_obligations_chirho(
        &fixture_chirho.storage_chirho,
        &fixture_chirho.held_signer_chirho,
        &fixture_chirho.losing_record_verifier_chirho,
        &subset_ports_chirho,
        &fixture_chirho.subset_checkpoint_chirho,
    )
    .expect("walk both pages of the subset-trap chain");
    assert_eq!(
        population_chirho.len(),
        1,
        "the obligation on the second-reached page must be discovered"
    );

    let proof_chirho = sealed_plan_proof_for_convergence_test_chirho(
        fixture_chirho.subset_identity_digest_chirho.clone(),
        fixture_chirho.subset_checkpoint_ref_chirho.clone(),
        fixture_chirho.subset_plan_ref_chirho.clone(),
        fixture_chirho.identity_chirho.winner_term_chirho,
        2,
        2,
        1,
    );
    let (mint_identity_digest_chirho, canonical_obligation_digest_chirho) =
        gd7_mint_identity_for_verified_obligation_chirho(
            &digest_chirho('e').0,
            &fixture_chirho.subset_checkpoint_ref_chirho,
            &fixture_chirho.subset_plan_ref_chirho,
            &fixture_chirho.subset_identity_digest_chirho,
            fixture_chirho.identity_chirho.winner_term_chirho,
            &population_chirho[0],
        )
        .expect("derive the second-page obligation's mint identity");

    // It is in the CLASSIFIED set, not merely the enumerated one: with no durable row it blocks
    // convergence and the refusal names it. A subset-enumerating regression would instead certify.
    assert_eq!(
        run_convergence_at_chirho(
            &fixture_chirho,
            &fixture_chirho.subset_checkpoint_chirho,
            &proof_chirho,
            convergence_binding_chirho(),
            satisfied_predicates_chirho(),
            balanced_conservation_snapshot_chirho(),
            &subset_ports_chirho,
        ),
        Err(Gd7PlanRefusalChirho::UnconvergedObligationChirho(
            mint_identity_digest_chirho.clone()
        )),
        "the second-page obligation must BLOCK convergence and name itself"
    );

    // Driven to Completed, the same chain certifies binding the signed count of 1.
    let state_chirho = create_convergence_row_chirho(
        &fixture_chirho,
        &mint_identity_digest_chirho,
        &canonical_obligation_digest_chirho,
    );
    drive_row_to_completed_chirho(&fixture_chirho, &state_chirho);
    let certificate_chirho = run_convergence_at_chirho(
        &fixture_chirho,
        &fixture_chirho.subset_checkpoint_chirho,
        &proof_chirho,
        convergence_binding_chirho(),
        satisfied_predicates_chirho(),
        balanced_conservation_snapshot_chirho(),
        &subset_ports_chirho,
    )
    .expect("a completed second-page obligation certifies");
    assert_eq!(certificate_chirho.population_count_chirho(), 1);
}

#[test]
fn convergence_refuses_an_unavailable_conservation_source_by_name_chirho() {
    // A12. Fail-closed: no verified snapshot means no measured conservation, so no certificate.
    // The refusal is asserted BY NAME, and it fires before the population walk — conservation is
    // the first thing the converger consumes after the coordinate shape check.
    struct UnavailableConservationSourceChirho;
    impl Gd7ConservationSnapshotSourcePortChirho for UnavailableConservationSourceChirho {
        fn load_signed_conservation_snapshot_chirho(
            &self,
        ) -> Result<SignedGd7ConservationSnapshotChirho, Gd7PlanRefusalChirho> {
            Err(Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)
        }
    }

    let fixture_chirho = obligation_mint_fixture_chirho("conservation-unavailable");
    let (mint_identity_digest_chirho, canonical_obligation_digest_chirho) =
        alternate_population_mint_identity_chirho(&fixture_chirho);
    let state_chirho = create_convergence_row_chirho(
        &fixture_chirho,
        &mint_identity_digest_chirho,
        &canonical_obligation_digest_chirho,
    );
    drive_row_to_completed_chirho(&fixture_chirho, &state_chirho);
    let proof_chirho = alternate_convergence_proof_chirho(&fixture_chirho, 1);

    // Control: with a source, this exact configuration certifies.
    run_convergence_chirho(
        &fixture_chirho,
        &proof_chirho,
        convergence_binding_chirho(),
        satisfied_predicates_chirho(),
    )
    .expect("control: an available conserving source certifies");

    let verifier_chirho = conservation_verifier_chirho();
    let source_chirho = UnavailableConservationSourceChirho;
    assert_eq!(
        run_convergence_with_ports_chirho(
            &fixture_chirho,
            &fixture_chirho.alternate_checkpoint_chirho,
            &proof_chirho,
            convergence_binding_chirho(),
            satisfied_predicates_chirho(),
            &Gd7ConservationProofPortsChirho::new_chirho(&source_chirho, &verifier_chirho),
        ),
        Err(Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho),
        "an unavailable conservation source must refuse by name, never certify"
    );
    // Nothing was persisted on the refusing path: the converger is read-only, and the immutable
    // fixture objects it read are byte-unchanged.
    fixture_chirho.assert_source_objects_unchanged_chirho();
}

#[test]
fn certificate_conservation_digest_tracks_the_verified_snapshot_chirho() {
    // A13. The bound digest must come from the snapshot the checker actually verified — not from a
    // caller-supplied value and not from a stale earlier run. Two runs over the SAME chain with two
    // different (both conserving) snapshots must bind two different digests, each equal to the
    // blake3 of that snapshot's own canonical line.
    let fixture_chirho = obligation_mint_fixture_chirho("conservation-digest-provenance");
    let (mint_identity_digest_chirho, canonical_obligation_digest_chirho) =
        alternate_population_mint_identity_chirho(&fixture_chirho);
    let state_chirho = create_convergence_row_chirho(
        &fixture_chirho,
        &mint_identity_digest_chirho,
        &canonical_obligation_digest_chirho,
    );
    drive_row_to_completed_chirho(&fixture_chirho, &state_chirho);
    let proof_chirho = alternate_convergence_proof_chirho(&fixture_chirho, 1);

    let first_snapshot_chirho = balanced_conservation_snapshot_chirho();
    // A different, still-conserving cut: different head coordinate and different balanced amount.
    let mut second_snapshot_chirho = balanced_conservation_snapshot_chirho();
    second_snapshot_chirho
        .head_chirho
        .covered_record_count_chirho = 9;
    second_snapshot_chirho.rollups_chirho[0].account_net_chirho = 2_500;
    second_snapshot_chirho.rollups_chirho[0].local_supply_chirho = 2_500;
    second_snapshot_chirho.global_supplies_chirho[0].supply_chirho = 2_500;
    assert_ne!(first_snapshot_chirho, second_snapshot_chirho);

    let first_certificate_chirho = run_convergence_at_chirho(
        &fixture_chirho,
        &fixture_chirho.alternate_checkpoint_chirho,
        &proof_chirho,
        convergence_binding_chirho(),
        satisfied_predicates_chirho(),
        first_snapshot_chirho.clone(),
        &fixture_chirho.effect_ports_chirho(),
    )
    .expect("the first conserving snapshot certifies");
    let second_certificate_chirho = run_convergence_at_chirho(
        &fixture_chirho,
        &fixture_chirho.alternate_checkpoint_chirho,
        &proof_chirho,
        convergence_binding_chirho(),
        satisfied_predicates_chirho(),
        second_snapshot_chirho.clone(),
        &fixture_chirho.effect_ports_chirho(),
    )
    .expect("the second conserving snapshot certifies");

    let expected_first_chirho = blake3::hash(
        gd7_conservation_snapshot_signed_content_line_chirho(&first_snapshot_chirho)
            .expect("canonicalize the first snapshot")
            .as_bytes(),
    )
    .to_hex()
    .to_string();
    let expected_second_chirho = blake3::hash(
        gd7_conservation_snapshot_signed_content_line_chirho(&second_snapshot_chirho)
            .expect("canonicalize the second snapshot")
            .as_bytes(),
    )
    .to_hex()
    .to_string();
    assert_eq!(
        first_certificate_chirho.conservation_snapshot_digest_chirho(),
        expected_first_chirho,
        "the bound digest must be the verified snapshot's own canonical digest"
    );
    assert_eq!(
        second_certificate_chirho.conservation_snapshot_digest_chirho(),
        expected_second_chirho
    );
    assert_ne!(
        first_certificate_chirho.conservation_snapshot_digest_chirho(),
        second_certificate_chirho.conservation_snapshot_digest_chirho(),
        "a changed source snapshot must move the bound digest, never retain a stale one"
    );
}

#[test]
fn convergence_refuses_a_resigned_snapshot_that_breaks_the_domain_drift_law_chirho() {
    // MONEY BAR. The tamper violates CONSERVATION specifically and is RE-SIGNED with the legitimate
    // key, so the signature check passes honestly and ONLY the conservation law can refuse. The
    // assertion names the law by TYPE and explicitly proves the refusal is not the signature — a
    // signature refusal here would mean conservation was never actually measured.
    let fixture_chirho = obligation_mint_fixture_chirho("conservation-domain-drift");
    let (mint_identity_digest_chirho, canonical_obligation_digest_chirho) =
        alternate_population_mint_identity_chirho(&fixture_chirho);
    let state_chirho = create_convergence_row_chirho(
        &fixture_chirho,
        &mint_identity_digest_chirho,
        &canonical_obligation_digest_chirho,
    );
    drive_row_to_completed_chirho(&fixture_chirho, &state_chirho);
    let proof_chirho = alternate_convergence_proof_chirho(&fixture_chirho, 1);

    // Control: this exact configuration certifies with the conserving snapshot, so the refusal
    // below is caused by the tamper rather than by a fixture that could never have converged.
    run_convergence_chirho(
        &fixture_chirho,
        &proof_chirho,
        convergence_binding_chirho(),
        satisfied_predicates_chirho(),
    )
    .expect("control: the conserving snapshot certifies");

    let mut drifted_chirho = balanced_conservation_snapshot_chirho();
    drifted_chirho.rollups_chirho[0].account_net_chirho = 999;
    let refusal_chirho = run_convergence_at_chirho(
        &fixture_chirho,
        &fixture_chirho.alternate_checkpoint_chirho,
        &proof_chirho,
        convergence_binding_chirho(),
        satisfied_predicates_chirho(),
        drifted_chirho,
        &fixture_chirho.effect_ports_chirho(),
    )
    .expect_err("an authentic snapshot whose account net drifts from local supply must refuse");
    assert!(
        matches!(
            &refusal_chirho,
            Gd7PlanRefusalChirho::ConservationIncidentChirho(incident_kind_chirho)
                if matches!(
                    **incident_kind_chirho,
                    ConservationIncidentKindChirho::DomainDriftChirho { .. }
                )
        ),
        "the refusal must be the domain drift law, got {refusal_chirho:?}"
    );
    assert_ne!(
        refusal_chirho,
        Gd7PlanRefusalChirho::InvalidConservationSnapshotSignatureChirho,
        "a re-signed tamper must NOT be caught by the signature check, or conservation is unmeasured"
    );
}

#[test]
fn convergence_refuses_a_resigned_snapshot_that_breaks_a_structural_law_chirho() {
    // The five STRUCTURAL laws are how a tampered snapshot would otherwise HIDE drift — by
    // duplicating, omitting, or orphaning a row rather than by moving a quantity. This arms one of
    // them (duplicate domain-kind rollup), also re-signed, to prove the host delegates the whole
    // checker rather than a two-law mirror of it.
    let fixture_chirho = obligation_mint_fixture_chirho("conservation-structural");
    let (mint_identity_digest_chirho, canonical_obligation_digest_chirho) =
        alternate_population_mint_identity_chirho(&fixture_chirho);
    let state_chirho = create_convergence_row_chirho(
        &fixture_chirho,
        &mint_identity_digest_chirho,
        &canonical_obligation_digest_chirho,
    );
    drive_row_to_completed_chirho(&fixture_chirho, &state_chirho);
    let proof_chirho = alternate_convergence_proof_chirho(&fixture_chirho, 1);

    // Every duplicated row is INTERNALLY conserving (account_net == local_supply), so neither drift
    // law can fire here: only a structural law can refuse this snapshot.
    let mut duplicated_chirho = balanced_conservation_snapshot_chirho();
    let duplicate_row_chirho = duplicated_chirho.rollups_chirho[0].clone();
    assert_eq!(
        duplicate_row_chirho.account_net_chirho, duplicate_row_chirho.local_supply_chirho,
        "the duplicated row must itself conserve, so only the structural law can refuse"
    );
    duplicated_chirho.rollups_chirho.push(duplicate_row_chirho);
    let refusal_chirho = run_convergence_at_chirho(
        &fixture_chirho,
        &fixture_chirho.alternate_checkpoint_chirho,
        &proof_chirho,
        convergence_binding_chirho(),
        satisfied_predicates_chirho(),
        duplicated_chirho,
        &fixture_chirho.effect_ports_chirho(),
    )
    .expect_err("an authentic snapshot with a duplicated domain-kind rollup must refuse");
    assert!(
        matches!(
            &refusal_chirho,
            Gd7PlanRefusalChirho::ConservationIncidentChirho(incident_kind_chirho)
                if matches!(
                    **incident_kind_chirho,
                    ConservationIncidentKindChirho::DuplicateDomainKindRollupChirho { .. }
                )
        ),
        "the refusal must be the duplicate-rollup structural law, got {refusal_chirho:?}"
    );
}

#[test]
fn convergence_refuses_an_unsigned_conservation_snapshot_tamper_chirho() {
    // The other side of the pair: a tamper that is NOT re-signed must refuse at the SIGNATURE, not
    // at a conservation law. Without this arm the two drift/structural arms above would not prove
    // the two refusals are distinguishable — a converger that refused everything with one error
    // would satisfy them.
    let fixture_chirho = obligation_mint_fixture_chirho("conservation-unsigned-tamper");
    let (mint_identity_digest_chirho, canonical_obligation_digest_chirho) =
        alternate_population_mint_identity_chirho(&fixture_chirho);
    let state_chirho = create_convergence_row_chirho(
        &fixture_chirho,
        &mint_identity_digest_chirho,
        &canonical_obligation_digest_chirho,
    );
    drive_row_to_completed_chirho(&fixture_chirho, &state_chirho);
    let proof_chirho = alternate_convergence_proof_chirho(&fixture_chirho, 1);

    let verifier_chirho = conservation_verifier_chirho();
    // Sign the CONSERVING snapshot, then swap the bytes for a drifted one, keeping the stale
    // signature. Both faults are present; the signature check must be the one that fires.
    let mut source_chirho =
        conservation_source_chirho(&verifier_chirho, balanced_conservation_snapshot_chirho());
    source_chirho.signed_chirho.snapshot_chirho.rollups_chirho[0].account_net_chirho = 999;
    let refusal_chirho = run_convergence_with_ports_chirho(
        &fixture_chirho,
        &fixture_chirho.alternate_checkpoint_chirho,
        &proof_chirho,
        convergence_binding_chirho(),
        satisfied_predicates_chirho(),
        &Gd7ConservationProofPortsChirho::new_chirho(&source_chirho, &verifier_chirho),
    )
    .expect_err("a snapshot whose signature no longer covers its bytes must refuse");
    assert_eq!(
        refusal_chirho,
        Gd7PlanRefusalChirho::InvalidConservationSnapshotSignatureChirho,
        "authenticity is checked BEFORE arithmetic, so an unsigned tamper refuses at the signature"
    );
}

#[test]
fn classifier_distinguishes_an_empty_population_from_an_unexamined_one_chirho() {
    let fixture_chirho = obligation_mint_fixture_chirho("convergence-empty");
    let (mint_identity_digest_chirho, canonical_obligation_digest_chirho) =
        alternate_population_mint_identity_chirho(&fixture_chirho);
    let proof_chirho = alternate_convergence_proof_chirho(&fixture_chirho, 1);

    let empty_evidence_chirho = classify_gd7_convergence_terminal_outcomes_chirho(
        &fixture_chirho.storage_chirho,
        &proof_chirho,
        &digest_chirho('e').0,
        &[],
        None,
    )
    .expect("an empty population classifies");
    assert_eq!(empty_evidence_chirho.measured_population_count_chirho(), 0);
    assert_eq!(empty_evidence_chirho.terminal_outcome_count_chirho(), 0);
    assert_eq!(empty_evidence_chirho.open_held_manual_count_chirho(), 0);

    // The same storage with a real one-obligation population must measure differently, so a zero
    // is a measured zero rather than the shape an unexamined scan would also produce.
    let state_chirho = create_convergence_row_chirho(
        &fixture_chirho,
        &mint_identity_digest_chirho,
        &canonical_obligation_digest_chirho,
    );
    drive_row_to_completed_chirho(&fixture_chirho, &state_chirho);
    let effect_ports_chirho = fixture_chirho.effect_ports_chirho();
    let population_chirho = enumerate_gd7_sealed_plan_obligations_chirho(
        &fixture_chirho.storage_chirho,
        &fixture_chirho.held_signer_chirho,
        &fixture_chirho.losing_record_verifier_chirho,
        &effect_ports_chirho,
        &fixture_chirho.alternate_checkpoint_chirho,
    )
    .expect("walk the complete two-page manifest chain");
    let populated_evidence_chirho = classify_gd7_convergence_terminal_outcomes_chirho(
        &fixture_chirho.storage_chirho,
        &proof_chirho,
        &digest_chirho('e').0,
        &population_chirho,
        None,
    )
    .expect("a real population classifies");
    assert_eq!(
        populated_evidence_chirho.measured_population_count_chirho(),
        1
    );
    assert_eq!(populated_evidence_chirho.terminal_outcome_count_chirho(), 1);
    assert_ne!(empty_evidence_chirho, populated_evidence_chirho);
}

/// Load a genuine plan page back out of the fixture's content-addressed store.
fn load_plan_page_bytes_chirho(
    fixture_chirho: &ObligationMintFixtureChirho,
    plan_page_ref_chirho: &str,
) -> Gd7ReconciliationPlanPageChirho {
    let path_chirho = gd7_reconciliation_plan_page_path_chirho(plan_page_ref_chirho)
        .expect("derive the plan page path");
    let bytes_chirho = fixture_chirho
        .storage_chirho
        .read_all_chirho(&path_chirho)
        .expect("read the plan page")
        .expect("the plan page exists");
    serde_json::from_slice(&bytes_chirho).expect("decode the plan page")
}

fn persist_plan_page_value_chirho(
    fixture_chirho: &ObligationMintFixtureChirho,
    page_chirho: &Gd7ReconciliationPlanPageChirho,
) -> String {
    let bytes_chirho = serde_json::to_vec(page_chirho).expect("encode the planted plan page");
    let digest_chirho = blake3::hash(&bytes_chirho).to_hex().to_string();
    persist_exact_bytes_chirho(
        &fixture_chirho.storage_chirho,
        &gd7_reconciliation_plan_page_path_chirho(&digest_chirho)
            .expect("derive the planted plan page path"),
        &bytes_chirho,
    );
    digest_chirho
}

#[test]
fn per_step_cumulative_divergence_refuses_naming_the_page_that_introduced_it_chirho() {
    // The divergence is planted on the NEWER page — the second step of the walk — so a refusal
    // proves the invariant is checked per step and attributes the fault to the right page, rather
    // than only comparing a grand total at the end. The pages are content-addressed, so the plant
    // is a genuinely re-addressed page, not an edit under an existing digest.
    let fixture_chirho = obligation_mint_fixture_chirho("cumulative-divergence");
    let older_page_chirho = load_plan_page_bytes_chirho(
        &fixture_chirho,
        &fixture_chirho.alternate_obligation_plan_ref_chirho,
    );
    let genuine_newer_ref_chirho = older_page_chirho
        .newer_plan_page_ref_chirho
        .clone()
        .expect("the alternate chain's older page links to a newer page");
    let mut planted_newer_page_chirho =
        load_plan_page_bytes_chirho(&fixture_chirho, &genuine_newer_ref_chirho);
    assert_eq!(
        planted_newer_page_chirho.cumulative_effect_obligation_count_chirho, 0,
        "the genuine newer page carries the chain-wide remainder this arm perturbs"
    );
    planted_newer_page_chirho.cumulative_effect_obligation_count_chirho = 1;
    let planted_newer_ref_chirho =
        persist_plan_page_value_chirho(&fixture_chirho, &planted_newer_page_chirho);
    assert_ne!(planted_newer_ref_chirho, genuine_newer_ref_chirho);

    let mut planted_older_page_chirho = older_page_chirho;
    planted_older_page_chirho.newer_plan_page_ref_chirho = Some(planted_newer_ref_chirho.clone());
    let planted_older_ref_chirho =
        persist_plan_page_value_chirho(&fixture_chirho, &planted_older_page_chirho);
    let (_planted_checkpoint_ref_chirho, planted_checkpoint_chirho) =
        persist_plan_checkpoint_chirho(
            &fixture_chirho.storage_chirho,
            &fixture_chirho.held_signer_chirho,
            &fixture_chirho.identity_chirho,
            &planted_older_page_chirho.manifest_page_ref_chirho,
            &planted_older_ref_chirho,
            2,
            2,
            1,
        );

    let effect_ports_chirho = fixture_chirho.effect_ports_chirho();
    let refusal_chirho = enumerate_gd7_sealed_plan_obligations_chirho(
        &fixture_chirho.storage_chirho,
        &fixture_chirho.held_signer_chirho,
        &fixture_chirho.losing_record_verifier_chirho,
        &effect_ports_chirho,
        &planted_checkpoint_chirho,
    )
    .expect_err("a diverged cumulative count must refuse");
    assert_eq!(
        refusal_chirho,
        Gd7PlanRefusalChirho::CumulativeDivergenceAtPlanPageChirho(planted_newer_ref_chirho),
        "the refusal must name the newer page that introduced the divergence, not the head"
    );
}
