// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Reviewer arms against the FROZEN D4 gate `restore_ordinary_writes_chirho`.
//!
//! These arms are the review. They are written against the gate AS LANDED at 33890278 and are not
//! permitted to change it: where an arm cannot pass, that is a finding reported to the coordinator,
//! not a defect fixed in the code under review. Each arm therefore states, in its own failure
//! message, what a future red MEANS — so whoever meets it inherits the measurement rather than the
//! archaeology.
//!
//! The parked-transaction arms next door (`write_restoration_tests_chirho`) drive
//! `commit_write_restoration_chirho` with FIXTURE-valued evidence. Everything here goes through the
//! production entry point instead, so the evidence coordinates are DERIVED by the gate and a caller
//! cannot substitute them.

use super::super::reconciliation_witness_tests_chirho::{
    empty_verified_losing_tail_chirho, held_winner_import_fixture_for_group_and_term_chirho,
    FakeGd7ControlSignerChirho, FakeWinnerLedgerSignerChirho,
};
use super::strand_fence_liveness_tests_chirho::{
    install_adopted_cut_in_resident_root_chirho, ElectorMeshChirho,
};
use super::with_unbound_resident_fixture_chirho;
use crate::reconciliation_chirho::{
    converged_read_replica_for_release_test_chirho,
    gd7_reconciliation_group_has_any_active_hold_chirho,
    gd7_reconciliation_group_ordinary_writes_withheld_chirho, plant_gd7_ordinary_write_hold_chirho,
    sign_converged_read_replica_for_test_chirho,
    signed_converged_read_replica_for_release_test_chirho,
    AuthenticatedGd7DeposedForkObservationChirho, ConvergedReadReplicaChirho,
    Gd7ReconciliationVerifierPortChirho, Gd7WinnerWitnessReaderChirho,
    GD7_CONVERGED_READ_REPLICA_SCHEMA_V2_CHIRHO,
};
use crate::resident_authority_chirho::write_restoration_chirho::{
    load_verified_write_restoration_confirmation_chirho, restore_ordinary_writes_chirho,
    Gd7WriteRestorationOutcomeChirho, Gd7WriteRestorationRefusalChirho,
};
use crate::{ResidentLedgerAuthorityChirho, ResidentLedgerAuthorityRefusalChirho};
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};

/// A v2 convergence certificate whose counts account for its own declared population.
///
/// Built here rather than borrowed from the release helper because that helper is v1, and the whole
/// point of the v2 arm is that the gate must tell them apart. Nothing about this value is signed —
/// see [`the_gate_accepts_a_caller_constructed_certificate_bound_to_nothing_chirho`], which is where
/// that fact is measured rather than assumed.
///
/// This models a certificate ALREADY bound to its adopted cut: it sets both `checkpoint_ref_chirho`
/// (the PlanSealed plan cut) and `adopted_checkpoint_ref_chirho` (the AdoptedHeld cut) to the same
/// value, which is the collapsed shape every non-adoption fixture uses. A GENUINE post-adoption
/// certificate distinguishes the two — see [`v2_certificate_with_cuts_chirho`], which the cut-binding
/// arm uses to prove the gate binds by the ADOPTED cut, not the plan cut.
fn v2_certificate_chirho(
    checkpoint_ref_chirho: &str,
    completed_count_chirho: u64,
    disposed_count_chirho: u64,
    population_count_chirho: u64,
    reconciliation_identity_chirho: &crate::reconciliation_chirho::Gd7ReconciliationIdentityChirho,
    winner_term_chirho: u64,
    signer_chirho: &dyn crate::reconciliation_chirho::Gd7ReconciliationSignerPortChirho,
) -> ConvergedReadReplicaChirho {
    v2_certificate_with_cuts_chirho(
        checkpoint_ref_chirho,
        checkpoint_ref_chirho,
        completed_count_chirho,
        disposed_count_chirho,
        population_count_chirho,
        reconciliation_identity_chirho,
        winner_term_chirho,
        signer_chirho,
    )
}

/// A v2 certificate whose PlanSealed plan cut and AdoptedHeld cut are supplied SEPARATELY.
///
/// A genuine converger distinguishes the two: `checkpoint_ref_chirho` is the PlanSealed plan cut where
/// obligations were sealed, and `adopted_checkpoint_ref_chirho` is the AdoptedHeld cut the gate
/// restores writes over. They are never equal after a real adoption. The gate loads and identity-checks
/// the cut at its `adopted_checkpoint_ref_chirho` PARAMETER, so a correct gate must bind the
/// certificate by the certificate's `adopted_checkpoint_ref_chirho`, not by its `checkpoint_ref_chirho`.
#[allow(
    clippy::too_many_arguments,
    reason = "the fixture mirrors the certificate's own field list rather than hiding cuts behind an aggregate the arm cannot vary"
)]
fn v2_certificate_with_cuts_chirho(
    plan_checkpoint_ref_chirho: &str,
    adopted_checkpoint_ref_chirho: &str,
    completed_count_chirho: u64,
    disposed_count_chirho: u64,
    population_count_chirho: u64,
    reconciliation_identity_chirho: &crate::reconciliation_chirho::Gd7ReconciliationIdentityChirho,
    winner_term_chirho: u64,
    signer_chirho: &dyn crate::reconciliation_chirho::Gd7ReconciliationSignerPortChirho,
) -> ConvergedReadReplicaChirho {
    let digest_chirho = |nibble_chirho: char| -> String { nibble_chirho.to_string().repeat(64) };
    let certificate_chirho = serde_json::from_value(serde_json::json!({
        "schema_chirho": GD7_CONVERGED_READ_REPLICA_SCHEMA_V2_CHIRHO,
        "reconciliation_identity_digest_chirho": crate::reconciliation_chirho::gd7_reconciliation_identity_digest_chirho(reconciliation_identity_chirho).unwrap(),
        "checkpoint_ref_chirho": plan_checkpoint_ref_chirho,
        "sealed_plan_ref_chirho": digest_chirho('b'),
        "winner_fork_witness_object_digest_chirho": digest_chirho('c'),
        "winner_term_chirho": winner_term_chirho,
        "adopted_checkpoint_ref_chirho": adopted_checkpoint_ref_chirho,
        "losing_population_identity_chirho": digest_chirho('e'),
        "losing_population_digest_chirho": digest_chirho('f'),
        "terminal_outcome_identity_chirho": digest_chirho('1'),
        "terminal_outcome_digest_chirho": digest_chirho('2'),
        "conservation_snapshot_digest_chirho": digest_chirho('4'),
        "retained_refs_chirho": [digest_chirho('3')],
        "population_count_chirho": population_count_chirho,
        "completed_count_chirho": completed_count_chirho,
        "disposed_count_chirho": disposed_count_chirho,
        "certificate_key_id_chirho": "",
        "certificate_sig_chirho": "",
    }))
    .expect("the v2 certificate fixture must match the landed certificate shape exactly");
    sign_converged_read_replica_for_test_chirho(certificate_chirho, signer_chirho)
}

/// One authenticated observation at a chosen winner term, signed by a chosen control key.
///
/// Both the reconciliation observation and the LATER elector grant are made this way, because the
/// gate's two parameters are the same type: the only thing that distinguishes a grant from the
/// victory it is supposed to postdate is the coordinates inside it, which is exactly what the arms
/// below probe.
fn authenticated_observation_chirho(
    storage_chirho: &crate::FsLedgerStorageChirho,
    control_signer_chirho: &FakeGd7ControlSignerChirho,
    ledger_signer_chirho: &FakeWinnerLedgerSignerChirho,
    losing_tail_label_chirho: &str,
    group_chirho: &ConsistencyGroupIdChirho,
    winner_term_chirho: u64,
) -> AuthenticatedGd7DeposedForkObservationChirho {
    let losing_tail_chirho = empty_verified_losing_tail_chirho(
        storage_chirho,
        ledger_signer_chirho,
        losing_tail_label_chirho,
    );
    let fixture_chirho = held_winner_import_fixture_for_group_and_term_chirho(
        storage_chirho,
        control_signer_chirho,
        ledger_signer_chirho,
        &losing_tail_chirho,
        group_chirho,
        winner_term_chirho,
    );
    Gd7WinnerWitnessReaderChirho::new_chirho(
        storage_chirho,
        control_signer_chirho,
        ledger_signer_chirho,
    )
    .import_authenticated_deposed_fork_observation_chirho(
        &fixture_chirho.identity_chirho,
        &fixture_chirho.index_bytes_chirho,
        &fixture_chirho.witness_bytes_chirho,
        &losing_tail_chirho,
    )
    .expect("import the genuine authenticated observation into the resident root")
}

/// Everything an arm needs once the instance is in D3-RELEASED state: head gone, sibling standing.
struct ReleasedInstanceChirho {
    storage_chirho: crate::FsLedgerStorageChirho,
    group_digest_chirho: String,
    adopted_ref_chirho: String,
    reconciliation_observation_chirho: AuthenticatedGd7DeposedForkObservationChirho,
    held_signer_chirho: FakeGd7ControlSignerChirho,
    ledger_signer_chirho: FakeWinnerLedgerSignerChirho,
    winner_term_chirho: u64,
}

/// Drive one group all the way to the released state through the LANDED machinery.
///
/// Real elector mesh, real reconciliation import, real adopted cut, real D3 release. No cell is
/// hand-poked: an arm that reached this state by writing objects directly would prove the gate
/// against a world the production path cannot produce.
fn release_one_instance_chirho(
    root_chirho: &std::path::Path,
    group_chirho: &ConsistencyGroupIdChirho,
    mesh_chirho: &ElectorMeshChirho,
    winner_term_chirho: u64,
    resident_chirho: &mut ResidentLedgerAuthorityChirho,
) -> ReleasedInstanceChirho {
    let storage_chirho = crate::FsLedgerStorageChirho::open_existing_chirho(root_chirho)
        .expect("open the resident root");
    let group_digest_chirho = consistency_group_digest_chirho(group_chirho).unwrap();
    let control_signer_chirho = FakeGd7ControlSignerChirho::new_chirho("a".repeat(64), 0x31);
    let ledger_signer_chirho = FakeWinnerLedgerSignerChirho::new_chirho(0x32);
    let reconciliation_observation_chirho = authenticated_observation_chirho(
        &storage_chirho,
        &control_signer_chirho,
        &ledger_signer_chirho,
        "d4gate-chirho",
        group_chirho,
        winner_term_chirho,
    );
    let held_signer_chirho = FakeGd7ControlSignerChirho::new_chirho(
        reconciliation_observation_chirho
            .identity_chirho()
            .held_node_chirho
            .clone(),
        0x41,
    );
    let adopted_ref_chirho = install_adopted_cut_in_resident_root_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &reconciliation_observation_chirho,
    );
    assert!(
        gd7_reconciliation_group_ordinary_writes_withheld_chirho(&storage_chirho, &group_digest_chirho)
            .expect("probe the ordinary-write hold"),
        "opening a reconciliation must plant the ordinary-write sibling, or every refusal arm below \
         is measuring an empty world"
    );
    resident_chirho
        .release_converged_gd7_hold_chirho(
            &adopted_ref_chirho,
            &signed_converged_read_replica_for_release_test_chirho(
                adopted_ref_chirho.clone(),
                &held_signer_chirho,
            ),
            &held_signer_chirho,
        )
        .expect("D3 releases the converged hold");
    assert!(
        !gd7_reconciliation_group_has_any_active_hold_chirho(&storage_chirho, &group_digest_chirho)
            .expect("probe the head after release"),
        "D3 must supersede the head"
    );
    assert!(
        gd7_reconciliation_group_ordinary_writes_withheld_chirho(
            &storage_chirho,
            &group_digest_chirho
        )
        .expect("probe the sibling after release"),
        "D3 must NOT lift the ordinary-write sibling — that is D4's act alone"
    );
    // The mesh is threaded in so a later arm can win a REAL later term over it; touching it here
    // keeps the borrow honest rather than leaving an unused parameter.
    assert!(
        mesh_chirho
            .node_chirho(1)
            .current_leadership_chirho()
            .is_leader_chirho,
        "node 1 still leads at the moment of release"
    );
    ReleasedInstanceChirho {
        storage_chirho,
        group_digest_chirho,
        adopted_ref_chirho,
        reconciliation_observation_chirho,
        held_signer_chirho,
        ledger_signer_chirho,
        winner_term_chirho,
    }
}

/// Open a bound resident on the mesh leader, exactly as the landed D4 arm next door does.
fn open_bound_resident_chirho<'a>(
    root_chirho: &std::path::Path,
    ports_chirho: crate::ResidentLedgerLocalPortsChirho<'a>,
    journal_path_chirho: &cairn_ledger_log_chirho::ports_chirho::StoragePathChirho,
    cluster_id_chirho: &ClusterIdChirho,
    mesh_chirho: &ElectorMeshChirho,
) -> ResidentLedgerAuthorityChirho<'a> {
    let birth_permit_chirho = crate::ResidentLedgerBirthPermitChirho::for_test_chirho(
        root_chirho,
        journal_path_chirho.clone(),
        cluster_id_chirho.clone(),
        0,
    );
    drop(
        ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
            birth_permit_chirho,
            ports_chirho,
            mesh_chirho
                .node_chirho(1)
                .local_append_authority_handle_chirho(),
        )
        .expect("bound resident is born on the mesh leader"),
    );
    ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
        root_chirho,
        ports_chirho,
        journal_path_chirho.clone(),
        cluster_id_chirho.clone(),
        0,
        mesh_chirho
            .node_chirho(1)
            .local_append_authority_handle_chirho(),
    )
    .expect("bound resident opens at its birth term")
}

// ===========================================================================================
// ARM 1 — THE HAPPY PATH, end to end through the production entry point.
// ===========================================================================================

/// The D4 property with a REAL later elector grant: refuse after D3, admit only after the gate.
///
/// The landed arm next door proved the barrier using `commit_write_restoration_chirho` with fixture
/// evidence. This one proves the GATE: the later grant is won by an actual multi-voter leadership
/// transfer on the elector mesh, imported as a second authenticated observation, and every field of
/// the confirmation is DERIVED by the gate from evidence it was handed — so the arm can assert the
/// derived coordinates by value rather than trusting a caller-supplied struct.
#[test]
fn the_gate_admits_ordinary_writes_only_after_a_real_later_election_grant_chirho() {
    with_unbound_resident_fixture_chirho(
        "d4gate-happy",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let mesh_chirho = ElectorMeshChirho::new_chirho(group_chirho, local_node_chirho);
            let winner_term_chirho = mesh_chirho.elect_chirho(1, None);
            let mut resident_chirho = open_bound_resident_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                &mesh_chirho,
            );

            // CONTROL, before any reconciliation exists. Without it a later refusal could be caused
            // by anything in the fixture and the arm would be measuring the wrong thing.
            resident_chirho
                .append_preactivation_chirho(
                    &crate::ResidentLedgerAppendPermitChirho::for_test_chirho(),
                    super::resident_mint_request_chirho(100, "d4gate-control-chirho"),
                )
                .expect("with no reconciliation open, an ordinary write must be admitted");

            let released_chirho = release_one_instance_chirho(
                root_chirho,
                group_chirho,
                &mesh_chirho,
                winner_term_chirho,
                &mut resident_chirho,
            );

            // AFTER D3 ALONE — still withheld. This is the half that makes the admit meaningful.
            let refusal_chirho = resident_chirho
                .append_preactivation_chirho(
                    &crate::ResidentLedgerAppendPermitChirho::for_test_chirho(),
                    super::resident_mint_request_chirho(100, "d4gate-after-release-chirho"),
                )
                .expect_err("after D3 alone, ordinary writes must still be withheld");
            assert!(
                matches!(
                    refusal_chirho,
                    ResidentLedgerAuthorityRefusalChirho::Gd7OrdinaryWritesWithheldChirho
                ),
                "the refusal must be the ORDINARY-WRITE barrier, not the head hold or a fence \
                 refusal. MIGRATION: Gd7ReconciliationHoldActiveChirho here means D3 stopped \
                 removing the head; a fence refusal means the fixture drifted and the barrier is \
                 untested. Got: {refusal_chirho:?}"
            );

            // THE LATER GRANT — a real leadership transfer, then back, so the term strictly
            // advances through authenticated raft traffic rather than a poked cell.
            mesh_chirho.elect_chirho(2, Some(1));
            let later_term_chirho = mesh_chirho.elect_chirho(1, Some(2));
            assert!(
                later_term_chirho > winner_term_chirho,
                "the elector mesh must actually advance the term: won {later_term_chirho}, \
                 reconciliation winner was {winner_term_chirho}"
            );
            let later_control_signer_chirho =
                FakeGd7ControlSignerChirho::new_chirho("9".repeat(64), 0x71);
            let later_observation_chirho = authenticated_observation_chirho(
                &released_chirho.storage_chirho,
                &later_control_signer_chirho,
                &released_chirho.ledger_signer_chirho,
                "d4gate-later-chirho",
                group_chirho,
                later_term_chirho,
            );

            let outcome_chirho = restore_ordinary_writes_chirho(
                &released_chirho.storage_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.reconciliation_observation_chirho,
                &later_observation_chirho,
                &v2_certificate_chirho(
                    &released_chirho.adopted_ref_chirho,
                    3,
                    1,
                    4,
                    released_chirho
                        .reconciliation_observation_chirho
                        .identity_chirho(),
                    released_chirho.winner_term_chirho,
                    &released_chirho.held_signer_chirho,
                ),
                &released_chirho.adopted_ref_chirho,
            )
            .expect("the D4 gate restores ordinary writes on complete evidence");
            assert_eq!(
                outcome_chirho,
                Gd7WriteRestorationOutcomeChirho::RestoredChirho,
                "the first restoration through the gate reports RestoredChirho"
            );

            // THE ADMIT HALF — the same append, the same resident, now admitted.
            resident_chirho
                .append_preactivation_chirho(
                    &crate::ResidentLedgerAppendPermitChirho::for_test_chirho(),
                    super::resident_mint_request_chirho(100, "d4gate-after-restore-chirho"),
                )
                .expect("after a gated restoration, ordinary writes are admitted again");

            // THE DERIVED COORDINATES. These are the fields the parked arm could only assert as
            // fixture values; here the gate produced them, so asserting them by VALUE is what
            // distinguishes "the gate ran" from "the gate derived the right instance".
            let confirmation_chirho = load_verified_write_restoration_confirmation_chirho(
                &released_chirho.storage_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.group_digest_chirho,
                &released_chirho.adopted_ref_chirho,
            )
            .expect("the confirmation reloads")
            .expect("the confirmation is present after a reported restoration");
            assert!(
                confirmation_chirho.head_absent_chirho(),
                "the confirmation carries the explicit absent-head marker"
            );
            assert_eq!(
                confirmation_chirho.accepted_winner_term_chirho(),
                winner_term_chirho,
                "the accepted winner term is derived from the RECONCILIATION observation"
            );
            assert_eq!(
                confirmation_chirho.elector_grant_term_chirho(),
                later_term_chirho,
                "the grant term is derived from the LATER observation, by value"
            );
            assert_eq!(
                confirmation_chirho.elector_grant_identity_chirho(),
                // Fully qualified: the fake carries a PRIVATE field of the same name, which field
                // syntax would resolve to instead of the port method the gate actually reads.
                <FakeGd7ControlSignerChirho as Gd7ReconciliationVerifierPortChirho>::key_id_chirho(
                    &later_control_signer_chirho,
                ),
                "the grant identity names the node that won the later term"
            );
            assert_eq!(
                confirmation_chirho.completed_count_chirho(),
                3,
                "completed count is derived from the v2 certificate"
            );
            assert_eq!(
                confirmation_chirho.disposed_count_chirho(),
                1,
                "disposed count is derived from the v2 certificate, separately from completed"
            );
            assert_eq!(
                confirmation_chirho
                    .verified_closed_population_total_chirho()
                    .expect("counts do not overflow"),
                4,
                "the closed population total is derived from its bound parts"
            );
        },
    );
}

/// The gate binds the certificate to the ADOPTED cut, not the PlanSealed plan cut.
///
/// This is the D4 analogue of brick R's release-door binding proof. Every other arm in this file
/// feeds the gate a certificate whose plan cut and adopted cut are COLLAPSED to one value, so they
/// cannot tell the two bindings apart — a gate that bound by `checkpoint_ref_chirho()` (the plan cut)
/// would pass all of them and still reject every genuine certificate. Here the certificate is GENUINE:
/// its `checkpoint_ref_chirho` (plan cut) is a distinct digest from its `adopted_checkpoint_ref_chirho`
/// (the adopted cut the gate is restoring), exactly as a real post-adoption certificate is. All other
/// evidence is the happy path's, so the ONLY thing that can refuse this is a mis-bound cut identity.
///
/// MIGRATION: if this now REFUSES with `ForeignCheckpointCertificateChirho`, the cut-identity binding
/// in `write_restoration_chirho.rs` regressed to `convergence_chirho.checkpoint_ref_chirho()` (the
/// plan cut). After a real adoption the plan cut and the adopted cut differ, so binding by the plan
/// cut can never admit a genuine certificate. It must bind by
/// `convergence_chirho.adopted_checkpoint_ref_chirho()` — the AdoptedHeld cut the gate loads and
/// identity-checks. The signature verification stays the authority gate: `adopted_checkpoint_ref_chirho`
/// is a signed field, so re-aiming a genuine certificate at another cut breaks that signature.
#[test]
fn the_gate_binds_the_certificate_by_its_adopted_cut_not_its_plan_cut_chirho() {
    with_unbound_resident_fixture_chirho(
        "d4gate-distinct-cut",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let mesh_chirho = ElectorMeshChirho::new_chirho(group_chirho, local_node_chirho);
            let winner_term_chirho = mesh_chirho.elect_chirho(1, None);
            let mut resident_chirho = open_bound_resident_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                &mesh_chirho,
            );

            let released_chirho = release_one_instance_chirho(
                root_chirho,
                group_chirho,
                &mesh_chirho,
                winner_term_chirho,
                &mut resident_chirho,
            );

            // A REAL later grant, exactly as the happy path wins it, so the only field that differs
            // from a restoring certificate is the distinct plan cut below.
            mesh_chirho.elect_chirho(2, Some(1));
            let later_term_chirho = mesh_chirho.elect_chirho(1, Some(2));
            assert!(
                later_term_chirho > winner_term_chirho,
                "the elector mesh must actually advance the term: won {later_term_chirho}, \
                 reconciliation winner was {winner_term_chirho}"
            );
            let later_control_signer_chirho =
                FakeGd7ControlSignerChirho::new_chirho("9".repeat(64), 0x71);
            let later_observation_chirho = authenticated_observation_chirho(
                &released_chirho.storage_chirho,
                &later_control_signer_chirho,
                &released_chirho.ledger_signer_chirho,
                "d4gate-distinct-later-chirho",
                group_chirho,
                later_term_chirho,
            );

            // THE PLAN CUT, distinct from the adopted cut. A genuine converger seals obligations at a
            // PlanSealed cut and later adopts a different AdoptedHeld cut; this models that difference.
            let plan_checkpoint_ref_chirho = "7".repeat(64);
            assert_ne!(
                plan_checkpoint_ref_chirho, released_chirho.adopted_ref_chirho,
                "the arm is only meaningful when the plan cut differs from the adopted cut"
            );

            let result_chirho = restore_ordinary_writes_chirho(
                &released_chirho.storage_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.reconciliation_observation_chirho,
                &later_observation_chirho,
                &v2_certificate_with_cuts_chirho(
                    &plan_checkpoint_ref_chirho,
                    &released_chirho.adopted_ref_chirho,
                    3,
                    1,
                    4,
                    released_chirho
                        .reconciliation_observation_chirho
                        .identity_chirho(),
                    released_chirho.winner_term_chirho,
                    &released_chirho.held_signer_chirho,
                ),
                &released_chirho.adopted_ref_chirho,
            );
            match result_chirho {
                Ok(Gd7WriteRestorationOutcomeChirho::RestoredChirho) => {}
                Err(Gd7WriteRestorationRefusalChirho::ForeignCheckpointCertificateChirho) => {
                    panic!(
                        "the D4 gate REFUSED a genuine post-adoption certificate whose plan cut \
                         differs from its adopted cut. The cut-identity binding regressed to \
                         `checkpoint_ref_chirho()` (the plan cut); after a real adoption plan cut != \
                         adopted cut, so binding by the plan cut can never admit a genuine \
                         certificate. Bind by `adopted_checkpoint_ref_chirho()` instead."
                    )
                }
                other_chirho => panic!(
                    "expected RestoredChirho for a genuine distinct-cut certificate; got \
                     {other_chirho:?}"
                ),
            }

            // The confirmation is stored keyed by the ADOPTED cut — the coordinate the gate bound and
            // loaded — not by the plan cut. Reloading it at the adopted ref proves the binding held all
            // the way to the durable artifact.
            let confirmation_chirho = load_verified_write_restoration_confirmation_chirho(
                &released_chirho.storage_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.group_digest_chirho,
                &released_chirho.adopted_ref_chirho,
            )
            .expect("the confirmation reloads")
            .expect("the confirmation is present after a reported restoration");
            assert_eq!(
                confirmation_chirho.retained_adopted_checkpoint_ref_chirho(),
                released_chirho.adopted_ref_chirho,
                "the confirmation retains the ADOPTED cut, confirming the gate bound by it"
            );
        },
    );
}

// ===========================================================================================
// ARM 2 — THE REFUSAL SET, each case BY NAME, against ONE released instance.
// ===========================================================================================

/// Every named refusal, plus the positive control that proves the state was restorable throughout.
///
/// One fixture, many probes, deliberately: a refusal suite split across fixtures can pass because
/// some earlier step silently failed, and the refusals would then be measuring an empty world. The
/// positive control at the end is what excludes that — the same coordinates that were refused six
/// times restore successfully once the missing evidence is supplied.
#[test]
fn the_gate_refuses_every_named_insufficient_evidence_case_chirho() {
    with_unbound_resident_fixture_chirho(
        "d4gate-refusals",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let mesh_chirho = ElectorMeshChirho::new_chirho(group_chirho, local_node_chirho);
            let winner_term_chirho = mesh_chirho.elect_chirho(1, None);
            let mut resident_chirho = open_bound_resident_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                &mesh_chirho,
            );
            let storage_chirho = crate::FsLedgerStorageChirho::open_existing_chirho(root_chirho)
                .expect("open the resident root");
            let group_digest_chirho = consistency_group_digest_chirho(group_chirho).unwrap();
            let control_signer_chirho =
                FakeGd7ControlSignerChirho::new_chirho("a".repeat(64), 0x31);
            let ledger_signer_chirho = FakeWinnerLedgerSignerChirho::new_chirho(0x32);
            let reconciliation_observation_chirho = authenticated_observation_chirho(
                &storage_chirho,
                &control_signer_chirho,
                &ledger_signer_chirho,
                "d4gate-refusals-chirho",
                group_chirho,
                winner_term_chirho,
            );
            let held_signer_chirho = FakeGd7ControlSignerChirho::new_chirho(
                reconciliation_observation_chirho
                    .identity_chirho()
                    .held_node_chirho
                    .clone(),
                0x41,
            );
            let adopted_ref_chirho = install_adopted_cut_in_resident_root_chirho(
                &storage_chirho,
                &held_signer_chirho,
                &reconciliation_observation_chirho,
            );

            // The later grant is won FIRST, so every refusal below fails for the reason it names
            // rather than because no valid grant existed yet.
            mesh_chirho.elect_chirho(2, Some(1));
            let later_term_chirho = mesh_chirho.elect_chirho(1, Some(2));
            let later_control_signer_chirho =
                FakeGd7ControlSignerChirho::new_chirho("9".repeat(64), 0x71);
            let later_observation_chirho = authenticated_observation_chirho(
                &storage_chirho,
                &later_control_signer_chirho,
                &ledger_signer_chirho,
                "d4gate-refusals-later-chirho",
                group_chirho,
                later_term_chirho,
            );

            // ---- CASE: UNRELEASED (head still present). Probed BEFORE D3, because that is the
            // only moment the head genuinely stands. Clause 10: "invoke D4 before release".
            //
            // WHAT THIS CASE DOES *NOT* ISOLATE, measured rather than assumed: the gate's
            // released-state test carries TWO conjuncts over the head — an authenticated load and
            // a bare presence test — and both resolve `gd7_reconciliation_group_head_path_chirho`,
            // both starting from `object_len_chirho`. A present head therefore makes the loader
            // return `Ok(Some(..))` or `Err(..)`; it returns `Ok(None)` only when the object is
            // absent, which is exactly when the presence test is false too. The presence conjunct
            // can never be the SOLE cause of a refusal, so no fixture can separate them and this
            // case pins "an unreleased instance refuses", not "the presence test is load-bearing".
            // Deleting the presence conjunct leaves this arm green; that is redundancy in the gate,
            // not a hole in it, and it is recorded here so the next reader does not re-derive it.
            let head_present_chirho = restore_ordinary_writes_chirho(
                &storage_chirho,
                &held_signer_chirho,
                &held_signer_chirho,
                &reconciliation_observation_chirho,
                &later_observation_chirho,
                &v2_certificate_chirho(
                    &adopted_ref_chirho,
                    3,
                    1,
                    4,
                    reconciliation_observation_chirho.identity_chirho(),
                    winner_term_chirho,
                    &held_signer_chirho,
                ),
                &adopted_ref_chirho,
            )
            .expect_err("D4 before D3 must refuse: the head is still standing");
            assert_eq!(
                head_present_chirho,
                Gd7WriteRestorationRefusalChirho::ActiveReconciliationChirho,
                "an unreleased instance must refuse by NAME as active reconciliation"
            );
            assert!(
                gd7_reconciliation_group_ordinary_writes_withheld_chirho(
                    &storage_chirho,
                    &group_digest_chirho
                )
                .expect("probe the sibling"),
                "a refused D4 must leave the sibling standing"
            );

            resident_chirho
                .release_converged_gd7_hold_chirho(
                    &adopted_ref_chirho,
                    &signed_converged_read_replica_for_release_test_chirho(
                        adopted_ref_chirho.clone(),
                        &held_signer_chirho,
                    ),
                    &held_signer_chirho,
                )
                .expect("D3 releases the converged hold");

            // ---- CASE: OLD-TERM GRANT, both edges. Equality must refuse and strictly-later must
            // be the only admitting relation; a `<` boundary slip would admit a grant from the
            // very term that lost.
            for (later_for_case_chirho, label_chirho) in [
                (
                    &reconciliation_observation_chirho,
                    "the winner's own term (equality)",
                ),
                (
                    &reconciliation_observation_chirho,
                    "no separate grant at all",
                ),
            ] {
                let refusal_chirho = restore_ordinary_writes_chirho(
                    &storage_chirho,
                    &held_signer_chirho,
                    &held_signer_chirho,
                    &reconciliation_observation_chirho,
                    later_for_case_chirho,
                    &v2_certificate_chirho(
                        &adopted_ref_chirho,
                        3,
                        1,
                        4,
                        reconciliation_observation_chirho.identity_chirho(),
                        winner_term_chirho,
                        &held_signer_chirho,
                    ),
                    &adopted_ref_chirho,
                )
                .expect_err("an old or absent grant must refuse");
                assert_eq!(
                    refusal_chirho,
                    Gd7WriteRestorationRefusalChirho::LaterElectorGrantRequiredChirho,
                    "{label_chirho} must refuse by NAME as a missing later grant"
                );
            }

            // ---- CASE: RECEIPT PRESENCE AS GRANT. Clause 10 names this explicitly: D4 never
            // treats a receipt, a restart, or a prior local term as a later grant. The released
            // instance now HAS its D3 receipt state; supplying no later observation must still
            // refuse for the grant reason and not become a released-state or certificate excuse.
            let receipt_only_chirho = restore_ordinary_writes_chirho(
                &storage_chirho,
                &held_signer_chirho,
                &held_signer_chirho,
                &reconciliation_observation_chirho,
                &reconciliation_observation_chirho,
                &v2_certificate_chirho(
                    &adopted_ref_chirho,
                    3,
                    1,
                    4,
                    reconciliation_observation_chirho.identity_chirho(),
                    winner_term_chirho,
                    &held_signer_chirho,
                ),
                &adopted_ref_chirho,
            )
            .expect_err("release evidence alone is not a later grant");
            assert_eq!(
                receipt_only_chirho,
                Gd7WriteRestorationRefusalChirho::LaterElectorGrantRequiredChirho,
                "a released instance with no later observation must refuse as a MISSING GRANT — if \
                 this ever reports ReleasedStateRequiredChirho, the gate started treating the \
                 released state itself as the grant, which is the inversion clause 13 forbids"
            );

            // ---- CASE: V1 CERTIFICATE. Clause 15: existing v1 certificates refuse through
            // verified_v2_counts_chirho. The release helper's certificate IS v1, so this arm also
            // proves D3 and D4 do not accept the same evidence tier.
            let v1_chirho = restore_ordinary_writes_chirho(
                &storage_chirho,
                &held_signer_chirho,
                &held_signer_chirho,
                &reconciliation_observation_chirho,
                &later_observation_chirho,
                &converged_read_replica_for_release_test_chirho(adopted_ref_chirho.clone()),
                &adopted_ref_chirho,
            )
            .expect_err("a v1 certificate carries defaulted zeros, not measured counts");
            assert_eq!(
                v1_chirho,
                Gd7WriteRestorationRefusalChirho::V2CertificateRequiredChirho,
                "a v1 certificate must refuse by NAME as a certificate failure"
            );

            // ---- CASE: COUNTS THAT DO NOT ACCOUNT FOR THE POPULATION. A v2 shape is not enough;
            // completed + disposed must equal the declared population or the certificate is
            // describing a population it did not close.
            let short_counts_chirho = restore_ordinary_writes_chirho(
                &storage_chirho,
                &held_signer_chirho,
                &held_signer_chirho,
                &reconciliation_observation_chirho,
                &later_observation_chirho,
                &v2_certificate_chirho(
                    &adopted_ref_chirho,
                    3,
                    1,
                    9,
                    reconciliation_observation_chirho.identity_chirho(),
                    winner_term_chirho,
                    &held_signer_chirho,
                ),
                &adopted_ref_chirho,
            )
            .expect_err("counts that leave part of the population unaccounted must refuse");
            assert_eq!(
                short_counts_chirho,
                Gd7WriteRestorationRefusalChirho::V2CertificateRequiredChirho,
                "an unaccounted population must refuse by NAME as a certificate failure"
            );

            // Nothing above may have restored anything.
            assert!(
                gd7_reconciliation_group_ordinary_writes_withheld_chirho(
                    &storage_chirho,
                    &group_digest_chirho
                )
                .expect("probe the sibling"),
                "no refusal in this set may lift the sibling"
            );
            assert!(
                load_verified_write_restoration_confirmation_chirho(
                    &storage_chirho,
                    &held_signer_chirho,
                    &group_digest_chirho,
                    &adopted_ref_chirho
                )
                .expect("probe the confirmation")
                .is_none(),
                "no refusal in this set may write a confirmation artifact"
            );

            // ---- THE POSITIVE CONTROL. The same coordinates, with the evidence supplied, restore.
            // Without this the six refusals above could all be a fixture that can never succeed.
            let restored_chirho = restore_ordinary_writes_chirho(
                &storage_chirho,
                &held_signer_chirho,
                &held_signer_chirho,
                &reconciliation_observation_chirho,
                &later_observation_chirho,
                &v2_certificate_chirho(
                    &adopted_ref_chirho,
                    3,
                    1,
                    4,
                    reconciliation_observation_chirho.identity_chirho(),
                    winner_term_chirho,
                    &held_signer_chirho,
                ),
                &adopted_ref_chirho,
            )
            .expect("the same instance restores once the evidence is complete");
            assert_eq!(
                restored_chirho,
                Gd7WriteRestorationOutcomeChirho::RestoredChirho,
                "the control must be a first restoration"
            );
        },
    );
}

/// FINDING ARM — an idempotent retry after a COMPLETED restoration refuses forever.
///
/// Clause 14 requires that D4 "retries idempotently", and
/// `Gd7WriteRestorationOutcomeChirho::AlreadyRestoredChirho` exists specifically so an operator can
/// tell a replay from a first success. `commit_write_restoration_chirho` implements that branch
/// correctly. The GATE cannot reach it: `restore_ordinary_writes_chirho` makes SIBLING-PRESENT a
/// conjunct of its released-state test, and a completed restoration has removed the sibling — so
/// the retry refuses `ReleasedStateRequiredChirho` before the idempotent branch is ever consulted.
///
/// This arm asserts the CONTRACTED behaviour and is therefore RED against the frozen gate. It is a
/// finding reported to the coordinator, not something to fix inside the code under review.
///
/// MIGRATION, for whoever meets this next: if it now PASSES, the fix landed and this arm becomes an
/// ordinary regression pin — leave it. If it fails with a refusal OTHER than
/// `ReleasedStateRequiredChirho`, the defect changed shape and the report needs re-measuring rather
/// than re-reading. If it fails claiming the FIRST restoration did not succeed, the fixture drifted
/// and the idempotency question was never reached.
#[test]
fn a_retry_after_a_completed_restoration_is_idempotent_rather_than_a_permanent_refusal_chirho() {
    with_unbound_resident_fixture_chirho(
        "d4gate-idempotent",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let mesh_chirho = ElectorMeshChirho::new_chirho(group_chirho, local_node_chirho);
            let winner_term_chirho = mesh_chirho.elect_chirho(1, None);
            let mut resident_chirho = open_bound_resident_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                &mesh_chirho,
            );
            let released_chirho = release_one_instance_chirho(
                root_chirho,
                group_chirho,
                &mesh_chirho,
                winner_term_chirho,
                &mut resident_chirho,
            );
            mesh_chirho.elect_chirho(2, Some(1));
            let later_term_chirho = mesh_chirho.elect_chirho(1, Some(2));
            let later_observation_chirho = authenticated_observation_chirho(
                &released_chirho.storage_chirho,
                &FakeGd7ControlSignerChirho::new_chirho("9".repeat(64), 0x71),
                &released_chirho.ledger_signer_chirho,
                "d4gate-idempotent-later-chirho",
                group_chirho,
                later_term_chirho,
            );
            let certificate_chirho = v2_certificate_chirho(
                &released_chirho.adopted_ref_chirho,
                3,
                1,
                4,
                released_chirho
                    .reconciliation_observation_chirho
                    .identity_chirho(),
                released_chirho.winner_term_chirho,
                &released_chirho.held_signer_chirho,
            );

            let first_chirho = restore_ordinary_writes_chirho(
                &released_chirho.storage_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.reconciliation_observation_chirho,
                &later_observation_chirho,
                &certificate_chirho,
                &released_chirho.adopted_ref_chirho,
            )
            .expect("the first restoration succeeds");
            assert_eq!(
                first_chirho,
                Gd7WriteRestorationOutcomeChirho::RestoredChirho,
                "the first call must be a first restoration, or the retry below tests nothing"
            );

            // THE RETRY. An operator whose process died between the gate's success and its own
            // record of that success re-runs the identical command. The confirmation is standing and
            // verifiable; the correct answer is AlreadyRestoredChirho.
            let retry_chirho = restore_ordinary_writes_chirho(
                &released_chirho.storage_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.reconciliation_observation_chirho,
                &later_observation_chirho,
                &certificate_chirho,
                &released_chirho.adopted_ref_chirho,
            );
            assert_eq!(
                retry_chirho,
                Ok(Gd7WriteRestorationOutcomeChirho::AlreadyRestoredChirho),
                "an identical retry over a standing, verified confirmation must be idempotent. \
                 KNOWN RED at 33890278: the gate's released-state test requires the sibling to be \
                 PRESENT, so a completed restoration makes every retry refuse \
                 ReleasedStateRequiredChirho — indistinguishable, to the operator, from a group \
                 that was never released at all."
            );
        },
    );
}

/// The inverse of the finding above, and it must hold under ANY fix: an absent sibling with NO
/// matching confirmation is not a restoration to confirm — it is an unexplained world, and the gate
/// must refuse rather than write a fresh confirmation over it.
///
/// This arm is what stops the obvious repair (allow an absent sibling) from becoming a second door.
#[test]
fn an_absent_sibling_without_a_matching_confirmation_still_refuses_chirho() {
    with_unbound_resident_fixture_chirho(
        "d4gate-no-sibling",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let mesh_chirho = ElectorMeshChirho::new_chirho(group_chirho, local_node_chirho);
            let winner_term_chirho = mesh_chirho.elect_chirho(1, None);
            let mut resident_chirho = open_bound_resident_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                &mesh_chirho,
            );
            let released_chirho = release_one_instance_chirho(
                root_chirho,
                group_chirho,
                &mesh_chirho,
                winner_term_chirho,
                &mut resident_chirho,
            );
            mesh_chirho.elect_chirho(2, Some(1));
            let later_term_chirho = mesh_chirho.elect_chirho(1, Some(2));
            let later_observation_chirho = authenticated_observation_chirho(
                &released_chirho.storage_chirho,
                &FakeGd7ControlSignerChirho::new_chirho("9".repeat(64), 0x71),
                &released_chirho.ledger_signer_chirho,
                "d4gate-no-sibling-later-chirho",
                group_chirho,
                later_term_chirho,
            );

            // Remove the sibling WITHOUT any restoration having happened — the shape a repair for
            // the idempotency defect must never mistake for "already restored".
            crate::reconciliation_chirho::remove_gd7_ordinary_write_hold_chirho(
                &released_chirho.storage_chirho,
                &released_chirho.group_digest_chirho,
            )
            .expect("clear the sibling to construct the unexplained state");
            assert!(
                load_verified_write_restoration_confirmation_chirho(
                    &released_chirho.storage_chirho,
                    &released_chirho.held_signer_chirho,
                    &released_chirho.group_digest_chirho,
                    &released_chirho.adopted_ref_chirho
                )
                .expect("probe the confirmation")
                .is_none(),
                "this arm requires NO confirmation to exist, or it is measuring the idempotent path"
            );

            let refusal_chirho = restore_ordinary_writes_chirho(
                &released_chirho.storage_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.reconciliation_observation_chirho,
                &later_observation_chirho,
                &v2_certificate_chirho(
                    &released_chirho.adopted_ref_chirho,
                    3,
                    1,
                    4,
                    released_chirho
                        .reconciliation_observation_chirho
                        .identity_chirho(),
                    released_chirho.winner_term_chirho,
                    &released_chirho.held_signer_chirho,
                ),
                &released_chirho.adopted_ref_chirho,
            )
            .expect_err("an absent sibling with no confirmation is unexplained, not restored");
            assert_eq!(
                refusal_chirho,
                Gd7WriteRestorationRefusalChirho::SiblingAbsentUnconfirmedChirho,
                "the unexplained state must refuse. MIGRATION: when the idempotency defect is \
                 fixed by admitting an absent sibling, this arm is the one that keeps the fix \
                 narrow — it must be conditioned on a VERIFIED matching confirmation, so this case \
                 stays red-on-admit."
            );
            assert!(
                load_verified_write_restoration_confirmation_chirho(
                    &released_chirho.storage_chirho,
                    &released_chirho.held_signer_chirho,
                    &released_chirho.group_digest_chirho,
                    &released_chirho.adopted_ref_chirho
                )
                .expect("probe the confirmation")
                .is_none(),
                "a refused gate must not leave a confirmation behind"
            );
        },
    );
}

// ===========================================================================================
// ARM 3 — THE STRANDLING PROBE.
// ===========================================================================================

/// THE STRANDLING: sibling present, no reconciliation evidence — the crash between plant and head.
///
/// The coordinator flagged gpt's conclusion ("the D4 gate is the required door") as assuming a
/// strandling can satisfy the gate's released-state, certificate, and grant requirements. This arm
/// measures it rather than reasoning about it, and the answer is worse than "the gate cannot clear
/// one": the gate CAN clear one, because none of its evidence is bound to a reconciliation that
/// actually happened. The released-state test reduces, in a strandling, to three absences plus one
/// presence — and all four are satisfied by a group that never reconciled.
#[test]
fn the_strandling_stays_withheld_without_a_durable_checkpoint_chirho() {
    with_unbound_resident_fixture_chirho(
        "d4gate-strandling",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let mesh_chirho = ElectorMeshChirho::new_chirho(group_chirho, local_node_chirho);
            let winner_term_chirho = mesh_chirho.elect_chirho(1, None);
            let mut resident_chirho = open_bound_resident_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                &mesh_chirho,
            );
            let storage_chirho = crate::FsLedgerStorageChirho::open_existing_chirho(root_chirho)
                .expect("open the resident root");
            let group_digest_chirho = consistency_group_digest_chirho(group_chirho).unwrap();

            // THE STRANDLING, constructed in the exact order the planting site uses: the sibling is
            // planted, and the crash happens before any checkpoint is committed. There is therefore
            // no head, no adopted cut, and no certificate an honest operator could produce.
            plant_gd7_ordinary_write_hold_chirho(&storage_chirho, &group_digest_chirho)
                .expect("plant the sibling, as commit_checkpoint_internal_chirho does");
            assert!(
                !gd7_reconciliation_group_has_any_active_hold_chirho(
                    &storage_chirho,
                    &group_digest_chirho
                )
                .expect("probe the head"),
                "a strandling has NO head — that is what makes it a strandling rather than a hold"
            );

            // The barrier is real: the group is stuck.
            let stuck_chirho = resident_chirho
                .append_preactivation_chirho(
                    &crate::ResidentLedgerAppendPermitChirho::for_test_chirho(),
                    super::resident_mint_request_chirho(100, "d4gate-strandling-chirho"),
                )
                .expect_err(
                    "a strandling withholds ordinary writes with no reconciliation to point at",
                );
            assert!(
                matches!(
                    stuck_chirho,
                    ResidentLedgerAuthorityRefusalChirho::Gd7OrdinaryWritesWithheldChirho
                ),
                "the strandling must withhold through the ordinary-write barrier. Got: {stuck_chirho:?}"
            );

            // THE PROBE. The operator has two authenticated observations (witnesses survive a crash
            // that lost the checkpoint) and invents the one coordinate nobody can check: an adopted
            // checkpoint ref, echoed by a certificate they construct to match it.
            let control_signer_chirho =
                FakeGd7ControlSignerChirho::new_chirho("a".repeat(64), 0x31);
            let ledger_signer_chirho = FakeWinnerLedgerSignerChirho::new_chirho(0x32);
            let reconciliation_observation_chirho = authenticated_observation_chirho(
                &storage_chirho,
                &control_signer_chirho,
                &ledger_signer_chirho,
                "d4gate-strandling-chirho",
                group_chirho,
                winner_term_chirho,
            );
            mesh_chirho.elect_chirho(2, Some(1));
            let later_term_chirho = mesh_chirho.elect_chirho(1, Some(2));
            let later_observation_chirho = authenticated_observation_chirho(
                &storage_chirho,
                &FakeGd7ControlSignerChirho::new_chirho("9".repeat(64), 0x71),
                &ledger_signer_chirho,
                "d4gate-strandling-later-chirho",
                group_chirho,
                later_term_chirho,
            );
            let held_signer_chirho = FakeGd7ControlSignerChirho::new_chirho(
                reconciliation_observation_chirho
                    .identity_chirho()
                    .held_node_chirho
                    .clone(),
                0x41,
            );
            let invented_ref_chirho = "7".repeat(64);
            assert!(
                crate::reconciliation_chirho::load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho(
                    &storage_chirho,
                    &held_signer_chirho,
                    &invented_ref_chirho,
                )
                .is_err(),
                "the invented adopted ref must name NO stored checkpoint, or this arm is describing \
                 a real cut and the strandling was never constructed"
            );

            let outcome_chirho = restore_ordinary_writes_chirho(
                &storage_chirho,
                &held_signer_chirho,
                &held_signer_chirho,
                &reconciliation_observation_chirho,
                &later_observation_chirho,
                &v2_certificate_chirho(
                    &invented_ref_chirho,
                    3,
                    1,
                    4,
                    reconciliation_observation_chirho.identity_chirho(),
                    later_term_chirho,
                    &held_signer_chirho,
                ),
                &invented_ref_chirho,
            );

            // A strandling has no durable checkpoint for the certificate to bind to. The gate must
            // refuse it and leave ordinary writes withheld until the separately scoped operator
            // door is built.
            assert_eq!(
                outcome_chirho,
                Err(Gd7WriteRestorationRefusalChirho::ForeignCheckpointCertificateChirho),
                "a strandling has no durable checkpoint for the certificate to bind to"
            );
            let strandling_refusal_chirho = resident_chirho
                .append_preactivation_chirho(
                    &crate::ResidentLedgerAppendPermitChirho::for_test_chirho(),
                    super::resident_mint_request_chirho(100, "d4gate-strandling-after-chirho"),
                )
                .expect_err("a strandling remains fail-closed without a durable release door");
            assert!(
                matches!(
                    strandling_refusal_chirho,
                    ResidentLedgerAuthorityRefusalChirho::Gd7OrdinaryWritesWithheldChirho
                ),
                "the strandling remains withheld by name: {strandling_refusal_chirho:?}"
            );
        },
    );
}

/// The general form of the caller-supplied certificate attack, isolated so it cannot be read as a
/// quirk of the strandling case: an unsigned certificate bound to nothing is rejected.
///
/// `ConvergedReadReplicaChirho` carries its signature through the verified loader before this gate
/// consumes it; this arm uses a caller-constructed value to exercise the gate's binding checks. The
/// gate reads exactly four things from it — schema, completed, disposed, population, checkpoint ref
/// — and checks only that the counts account for the population and that the checkpoint ref equals
/// the OTHER value the same caller supplied. Its `reconciliation_identity_digest_chirho`,
/// `winner_term_chirho`, and `adopted_checkpoint_ref_chirho` are never read.
///
/// Design clause 5 requires "a valid B3b `ConvergedReadReplicaChirho` ... bound to the full D1
/// population, completed count, disposed count, terminal digests, accepted checkpoint, winner, and
/// retained refs". This arm measures the distance between that clause and the gate.
#[test]
fn the_gate_rejects_a_caller_constructed_certificate_bound_to_nothing_chirho() {
    with_unbound_resident_fixture_chirho(
        "d4gate-cert-binding",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let mesh_chirho = ElectorMeshChirho::new_chirho(group_chirho, local_node_chirho);
            let winner_term_chirho = mesh_chirho.elect_chirho(1, None);
            let mut resident_chirho = open_bound_resident_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                &mesh_chirho,
            );
            let released_chirho = release_one_instance_chirho(
                root_chirho,
                group_chirho,
                &mesh_chirho,
                winner_term_chirho,
                &mut resident_chirho,
            );
            mesh_chirho.elect_chirho(2, Some(1));
            let later_term_chirho = mesh_chirho.elect_chirho(1, Some(2));
            let later_observation_chirho = authenticated_observation_chirho(
                &released_chirho.storage_chirho,
                &FakeGd7ControlSignerChirho::new_chirho("9".repeat(64), 0x71),
                &released_chirho.ledger_signer_chirho,
                "d4gate-cert-later-chirho",
                group_chirho,
                later_term_chirho,
            );

            // A certificate describing a DIFFERENT reconciliation, a DIFFERENT winner term, and a
            // DIFFERENT adopted checkpoint from the instance being restored. Its `checkpoint_ref_chirho`
            // (the PlanSealed plan cut) is made to echo the adopted ref — the field the OLD, mis-bound
            // gate keyed on — precisely to prove the FIXED gate no longer keys on it: the gate binds by
            // the certificate's `adopted_checkpoint_ref_chirho`, which here is foreign.
            let foreign_certificate_chirho = {
                let digest_chirho =
                    |nibble_chirho: char| -> String { nibble_chirho.to_string().repeat(64) };
                serde_json::from_value::<ConvergedReadReplicaChirho>(serde_json::json!({
                    "schema_chirho": GD7_CONVERGED_READ_REPLICA_SCHEMA_V2_CHIRHO,
                    "reconciliation_identity_digest_chirho": digest_chirho('0'),
                    "checkpoint_ref_chirho": released_chirho.adopted_ref_chirho,
                    "sealed_plan_ref_chirho": digest_chirho('0'),
                    "winner_fork_witness_object_digest_chirho": digest_chirho('0'),
                    "winner_term_chirho": 999_999u64,
                    "adopted_checkpoint_ref_chirho": digest_chirho('0'),
                    "losing_population_identity_chirho": digest_chirho('0'),
                    "losing_population_digest_chirho": digest_chirho('0'),
                    "terminal_outcome_identity_chirho": digest_chirho('0'),
                    "terminal_outcome_digest_chirho": digest_chirho('0'),
                    "conservation_snapshot_digest_chirho": digest_chirho('0'),
                    "retained_refs_chirho": [],
                    "population_count_chirho": 0u64,
                    "completed_count_chirho": 0u64,
                    "disposed_count_chirho": 0u64,
                    "certificate_key_id_chirho": "",
                    "certificate_sig_chirho": "",
                }))
                .expect("the foreign certificate fixture matches the landed shape")
            };

            let outcome_chirho = restore_ordinary_writes_chirho(
                &released_chirho.storage_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.reconciliation_observation_chirho,
                &later_observation_chirho,
                &foreign_certificate_chirho,
                &released_chirho.adopted_ref_chirho,
            );

            // REFUSED BY NAME at the cut-identity binding — the migration this arm's prior revision
            // anticipated. Once the gate binds the certificate to stored evidence by its
            // `adopted_checkpoint_ref_chirho` (fixed here to mirror brick R's release-door binding), a
            // certificate whose adopted cut is foreign refuses HERE, before the signature loader the old
            // mis-binding let it reach only because it was also unsigned. Under the OLD binding this
            // returned `V2CertificateRequiredChirho`, and a SIGNED echo of this shape would have slipped
            // the binding entirely. The zero population is kept so "no obligations were open" and "no
            // population was ever measured" stay distinguishable.
            assert_eq!(
                outcome_chirho,
                Err(Gd7WriteRestorationRefusalChirho::ForeignCheckpointCertificateChirho),
                "a certificate whose adopted checkpoint is foreign refuses at the cut-identity binding"
            );
            let confirmation_chirho = load_verified_write_restoration_confirmation_chirho(
                &released_chirho.storage_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.group_digest_chirho,
                &released_chirho.adopted_ref_chirho,
            )
            .expect("the confirmation lookup succeeds");
            assert!(
                confirmation_chirho.is_none(),
                "a refused foreign certificate writes no confirmation"
            );
        },
    );
}

// ===========================================================================================
// ARM 4 — THE CRASH WINDOW, through the real gate.
// ===========================================================================================

/// Clause 14's crash window: confirmation durable, sibling still standing. Retry must complete it.
///
/// The state is reconstructed rather than crashed into — run the gate, then re-plant the sibling —
/// which reproduces exactly the durable shape a crash between the artifact's verification and the
/// hold's removal leaves behind. The arm also pins the half that matters most: while the artifact is
/// down but the sibling stands, NOTHING is admitted. A confirmation is not permission.
#[test]
fn a_crash_between_the_artifact_and_the_hold_removal_completes_on_retry_chirho() {
    with_unbound_resident_fixture_chirho(
        "d4gate-crash-window",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let mesh_chirho = ElectorMeshChirho::new_chirho(group_chirho, local_node_chirho);
            let winner_term_chirho = mesh_chirho.elect_chirho(1, None);
            let mut resident_chirho = open_bound_resident_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                &mesh_chirho,
            );
            let released_chirho = release_one_instance_chirho(
                root_chirho,
                group_chirho,
                &mesh_chirho,
                winner_term_chirho,
                &mut resident_chirho,
            );
            mesh_chirho.elect_chirho(2, Some(1));
            let later_term_chirho = mesh_chirho.elect_chirho(1, Some(2));
            let later_observation_chirho = authenticated_observation_chirho(
                &released_chirho.storage_chirho,
                &FakeGd7ControlSignerChirho::new_chirho("9".repeat(64), 0x71),
                &released_chirho.ledger_signer_chirho,
                "d4gate-crash-later-chirho",
                group_chirho,
                later_term_chirho,
            );
            let certificate_chirho = v2_certificate_chirho(
                &released_chirho.adopted_ref_chirho,
                3,
                1,
                4,
                released_chirho
                    .reconciliation_observation_chirho
                    .identity_chirho(),
                released_chirho.winner_term_chirho,
                &released_chirho.held_signer_chirho,
            );

            restore_ordinary_writes_chirho(
                &released_chirho.storage_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.reconciliation_observation_chirho,
                &later_observation_chirho,
                &certificate_chirho,
                &released_chirho.adopted_ref_chirho,
            )
            .expect("the artifact is written and verified");

            // RECONSTRUCT THE CRASH STATE: artifact durable, sibling standing.
            plant_gd7_ordinary_write_hold_chirho(
                &released_chirho.storage_chirho,
                &released_chirho.group_digest_chirho,
            )
            .expect("re-plant the sibling to reconstruct the interrupted transaction");
            assert!(
                gd7_reconciliation_group_ordinary_writes_withheld_chirho(
                    &released_chirho.storage_chirho,
                    &released_chirho.group_digest_chirho
                )
                .expect("probe the sibling"),
                "the crash state requires the sibling to stand, or this arm measures the completed \
                 state instead"
            );

            // NOTHING ADMITS BETWEEN. The confirmation is durable and verifiable, and it grants
            // nothing — the append funnel has no read path to it, and the sibling still withholds.
            let refusal_chirho = resident_chirho
                .append_preactivation_chirho(
                    &crate::ResidentLedgerAppendPermitChirho::for_test_chirho(),
                    super::resident_mint_request_chirho(100, "d4gate-crash-window-chirho"),
                )
                .expect_err("a durable confirmation is not permission while the sibling stands");
            assert!(
                matches!(
                    refusal_chirho,
                    ResidentLedgerAuthorityRefusalChirho::Gd7OrdinaryWritesWithheldChirho
                ),
                "presence of a verified confirmation must never grant. Got: {refusal_chirho:?}"
            );

            // THE RETRY completes the transaction and reports the replay distinctly.
            let retry_chirho = restore_ordinary_writes_chirho(
                &released_chirho.storage_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.reconciliation_observation_chirho,
                &later_observation_chirho,
                &certificate_chirho,
                &released_chirho.adopted_ref_chirho,
            )
            .expect("the interrupted restoration completes on retry");
            assert_eq!(
                retry_chirho,
                Gd7WriteRestorationOutcomeChirho::AlreadyRestoredChirho,
                "the retry over a standing artifact is a REPLAY, distinguishable from a first \
                 success — and this is the state in which the gate CAN reach that branch, which is \
                 precisely what makes the completed-state retry defect a narrow one"
            );
            resident_chirho
                .append_preactivation_chirho(
                    &crate::ResidentLedgerAppendPermitChirho::for_test_chirho(),
                    super::resident_mint_request_chirho(100, "d4gate-crash-recovered-chirho"),
                )
                .expect("after the retry completes, ordinary writes are admitted");
        },
    );
}

// ===========================================================================================
// ARM 5 — MY OWN ARM, pre-registered before its verdict was known.
// ===========================================================================================

/// Design clause 1's own ARMS line: "use ... a witness from another group ... [it] must refuse
/// before restoring writes." This arm supplies exactly that and measures the gate.
///
/// The gate reads the LATER observation for two values only — `winner_term_chirho` and
/// `winner_node_chirho` — and resolves every storage coordinate from the RECONCILIATION
/// observation's group. The two are never compared. Raft terms are per-group counters, so a term
/// from a foreign group is not later than anything here; it is a number from a different sequence.
///
/// I registered this arm to the coordinator before running it, because I found it by reading the
/// gate and a favourable result would otherwise have been mine to quietly drop.
#[test]
fn a_later_grant_from_a_foreign_consistency_group_must_not_restore_writes_chirho() {
    with_unbound_resident_fixture_chirho(
        "d4gate-foreign-group",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let mesh_chirho = ElectorMeshChirho::new_chirho(group_chirho, local_node_chirho);
            let winner_term_chirho = mesh_chirho.elect_chirho(1, None);
            let mut resident_chirho = open_bound_resident_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                &mesh_chirho,
            );
            let released_chirho = release_one_instance_chirho(
                root_chirho,
                group_chirho,
                &mesh_chirho,
                winner_term_chirho,
                &mut resident_chirho,
            );

            // A grant belonging to a DIFFERENT consistency group. No election happened in the group
            // being restored; this term was won somewhere else entirely.
            let foreign_group_chirho = ConsistencyGroupIdChirho::TenantChirho {
                tenant_id_chirho: "d4gate-foreign-tenant-chirho".to_owned(),
            };
            assert_ne!(
                consistency_group_digest_chirho(&foreign_group_chirho).unwrap(),
                released_chirho.group_digest_chirho,
                "the foreign group must actually differ, or this arm is testing the same group"
            );
            let foreign_observation_chirho = authenticated_observation_chirho(
                &released_chirho.storage_chirho,
                &FakeGd7ControlSignerChirho::new_chirho("9".repeat(64), 0x71),
                &released_chirho.ledger_signer_chirho,
                "d4gate-foreign-later-chirho",
                &foreign_group_chirho,
                winner_term_chirho + 1,
            );
            assert_ne!(
                foreign_observation_chirho
                    .identity_chirho()
                    .consistency_group_digest_chirho,
                released_chirho.group_digest_chirho,
                "the observation must carry the foreign group, or the fixture did not build one"
            );

            let outcome_chirho = restore_ordinary_writes_chirho(
                &released_chirho.storage_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.reconciliation_observation_chirho,
                &foreign_observation_chirho,
                &v2_certificate_chirho(
                    &released_chirho.adopted_ref_chirho,
                    3,
                    1,
                    4,
                    released_chirho
                        .reconciliation_observation_chirho
                        .identity_chirho(),
                    released_chirho.winner_term_chirho,
                    &released_chirho.held_signer_chirho,
                ),
                &released_chirho.adopted_ref_chirho,
            );

            // MIGRATION: when the gate compares the two groups, this becomes an ordinary refusal
            // pin — retarget the assertion to the refusal's own name and keep the fixture, because
            // an unchanged fixture makes the new green a statement about the CODE rather than about
            // the test.
            // RETARGETED at the fix, fixture untouched: `is_err()` was the right assertion while
            // the outcome was Ok(RestoredChirho), and it is the wrong one now. A group mismatch
            // swallowed into a released-state or certificate refusal would still be "an error",
            // and would hide that the GROUP is what the gate rejected.
            assert_eq!(
                outcome_chirho,
                Err(Gd7WriteRestorationRefusalChirho::ForeignGroupChirho),
                "a grant from a foreign consistency group must refuse BY NAME — clause 1's own \
                 ARMS line. This was RED at 33890278 (Ok(RestoredChirho)): the gate compared \
                 winner terms across groups without ever comparing the groups. Got: \
                 {outcome_chirho:?}"
            );
            assert!(
                gd7_reconciliation_group_ordinary_writes_withheld_chirho(
                    &released_chirho.storage_chirho,
                    &released_chirho.group_digest_chirho
                )
                .expect("probe the sibling"),
                "a foreign-group grant must leave the sibling standing"
            );
        },
    );
}

// ===========================================================================================
// DELTA ARMS — owed at 086d74be, written against the fix at 3be78ffc.
// ===========================================================================================

/// The arm I owed when I pre-registered the delta criteria: the sibling-absent relaxation must turn
/// on a confirmation that VERIFIES, never on one that is merely PRESENT.
///
/// The repair for the idempotency defect admits an absent sibling when a matching confirmation
/// stands. "A confirmation is present" and "the matching one verifies" are one careless `is_some()`
/// apart, and that distance is the whole ruling: if presence alone sufficed, a corrupt or foreign
/// artifact at the instance path would re-admit ordinary writes — the presence-grants inversion
/// clause 7 exists to forbid, arriving through the confirmation instead of through the hold.
///
/// The fixture reaches the state the only way production can: a real gated restoration, then a
/// tamper of the durable artifact. Nothing about the gate is stubbed.
#[test]
fn a_present_but_unverifiable_confirmation_does_not_satisfy_the_sibling_absent_relaxation_chirho() {
    with_unbound_resident_fixture_chirho(
        "d4gate-tampered-confirmation",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let mesh_chirho = ElectorMeshChirho::new_chirho(group_chirho, local_node_chirho);
            let winner_term_chirho = mesh_chirho.elect_chirho(1, None);
            let mut resident_chirho = open_bound_resident_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                &mesh_chirho,
            );
            let released_chirho = release_one_instance_chirho(
                root_chirho,
                group_chirho,
                &mesh_chirho,
                winner_term_chirho,
                &mut resident_chirho,
            );
            mesh_chirho.elect_chirho(2, Some(1));
            let later_term_chirho = mesh_chirho.elect_chirho(1, Some(2));
            let later_observation_chirho = authenticated_observation_chirho(
                &released_chirho.storage_chirho,
                &FakeGd7ControlSignerChirho::new_chirho("9".repeat(64), 0x71),
                &released_chirho.ledger_signer_chirho,
                "d4gate-tampered-later-chirho",
                group_chirho,
                later_term_chirho,
            );
            let certificate_chirho = v2_certificate_chirho(
                &released_chirho.adopted_ref_chirho,
                3,
                1,
                4,
                released_chirho
                    .reconciliation_observation_chirho
                    .identity_chirho(),
                released_chirho.winner_term_chirho,
                &released_chirho.held_signer_chirho,
            );

            restore_ordinary_writes_chirho(
                &released_chirho.storage_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.reconciliation_observation_chirho,
                &later_observation_chirho,
                &certificate_chirho,
                &released_chirho.adopted_ref_chirho,
            )
            .expect("the first restoration succeeds and removes the sibling");

            // TAMPER the durable confirmation in place. The object stays PRESENT at the instance
            // path — so any presence-only test still sees it — but it can no longer verify.
            let path_chirho =
                crate::resident_authority_chirho::write_restoration_chirho::gd7_write_restoration_confirmation_path_chirho(
                    &released_chirho.group_digest_chirho,
                    &released_chirho.adopted_ref_chirho,
                )
                .expect("resolve the confirmation path");
            let original_bytes_chirho =
                cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho::read_all_chirho(
                    &released_chirho.storage_chirho,
                    &path_chirho,
                )
                .expect("read the confirmation")
                .expect("the confirmation is present after a reported restoration");
            let original_text_chirho =
                std::str::from_utf8(&original_bytes_chirho).expect("the confirmation is utf8");
            let needle_chirho = "\"completed_count_chirho\":3";
            assert!(
                original_text_chirho.contains(needle_chirho),
                "the tamper anchor must exist in the artifact, or this arm tests nothing. \
                 MIGRATION: if the field was renamed or the fixture count changed, retarget the \
                 anchor — do not delete the case."
            );
            let tampered_text_chirho =
                original_text_chirho.replace(needle_chirho, "\"completed_count_chirho\":4");
            assert_ne!(
                tampered_text_chirho.as_bytes(),
                original_bytes_chirho.as_slice(),
                "the tamper must actually change the bytes"
            );
            cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho::remove_chirho(
                &released_chirho.storage_chirho,
                &path_chirho,
            )
            .expect("clear the artifact so the tampered bytes can take its place");
            cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho::create_durable_chirho(
                &released_chirho.storage_chirho,
                &path_chirho,
                tampered_text_chirho.as_bytes(),
            )
            .expect("write the tampered artifact");

            // THE STATE THIS ARM EXISTS FOR: sibling ABSENT, confirmation PRESENT, confirmation
            // UNVERIFIABLE. A presence-only relaxation admits here; a verified one refuses.
            assert!(
                !gd7_reconciliation_group_ordinary_writes_withheld_chirho(
                    &released_chirho.storage_chirho,
                    &released_chirho.group_digest_chirho
                )
                .expect("probe the sibling"),
                "this arm requires the sibling to be ABSENT, or it is measuring the ordinary path"
            );
            assert!(
                load_verified_write_restoration_confirmation_chirho(
                    &released_chirho.storage_chirho,
                    &released_chirho.held_signer_chirho,
                    &released_chirho.group_digest_chirho,
                    &released_chirho.adopted_ref_chirho
                )
                .is_err(),
                "this arm requires the tampered artifact to FAIL verification, or the tamper missed"
            );

            let refusal_chirho = restore_ordinary_writes_chirho(
                &released_chirho.storage_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.reconciliation_observation_chirho,
                &later_observation_chirho,
                &certificate_chirho,
                &released_chirho.adopted_ref_chirho,
            )
            .expect_err("a present-but-unverifiable confirmation is not a matching confirmation");
            assert!(
                matches!(
                    refusal_chirho,
                    Gd7WriteRestorationRefusalChirho::SiblingAbsentUnconfirmedChirho
                        | Gd7WriteRestorationRefusalChirho::StorageChirho
                ),
                "the refusal must come from the confirmation check failing closed. MIGRATION: if \
                 this reports RestoredChirho, the relaxation degraded to a presence test and the \
                 idempotency repair has become the second door it was narrowed to avoid. Got: \
                 {refusal_chirho:?}"
            );
        },
    );
}

/// The zero-population case, kept alive as I pre-committed, now that the unsigned path is closed.
///
/// The counts a certificate carries are still CHOSEN BY ITS SIGNER: nothing joins them to an
/// enumerated obligation population. That join is ruled out of this brick and into CHAIN-CERT-1, so
/// this arm pins the MEASURED consequence rather than asserting a refusal the ruling did not ask
/// for — a signed certificate binding a real stored checkpoint, declaring a population of ZERO,
/// restores, and the signed confirmation then attests that zero as closed-population evidence.
///
/// It exists so the deferral stays visible and cannot be mistaken for coverage. MIGRATION: when
/// CHAIN-CERT-1 joins the counts to the enumerated population, this arm goes RED — retarget it to
/// assert the refusal by name and KEEP the zero case, because "no obligations were open" and "no
/// population was ever measured" must not remain the same value.
#[test]
fn a_signed_certificate_may_still_declare_a_zero_population_until_chain_cert_1_chirho() {
    with_unbound_resident_fixture_chirho(
        "d4gate-zero-population",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let mesh_chirho = ElectorMeshChirho::new_chirho(group_chirho, local_node_chirho);
            let winner_term_chirho = mesh_chirho.elect_chirho(1, None);
            let mut resident_chirho = open_bound_resident_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                &mesh_chirho,
            );
            let released_chirho = release_one_instance_chirho(
                root_chirho,
                group_chirho,
                &mesh_chirho,
                winner_term_chirho,
                &mut resident_chirho,
            );
            mesh_chirho.elect_chirho(2, Some(1));
            let later_term_chirho = mesh_chirho.elect_chirho(1, Some(2));
            let later_observation_chirho = authenticated_observation_chirho(
                &released_chirho.storage_chirho,
                &FakeGd7ControlSignerChirho::new_chirho("9".repeat(64), 0x71),
                &released_chirho.ledger_signer_chirho,
                "d4gate-zero-population-later-chirho",
                group_chirho,
                later_term_chirho,
            );

            // Every binding the fix added is satisfied: real identity digest, real winner term,
            // real stored checkpoint, signed by the held key. Only the COUNTS are invented.
            let outcome_chirho = restore_ordinary_writes_chirho(
                &released_chirho.storage_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.reconciliation_observation_chirho,
                &later_observation_chirho,
                &v2_certificate_chirho(
                    &released_chirho.adopted_ref_chirho,
                    0,
                    0,
                    0,
                    released_chirho
                        .reconciliation_observation_chirho
                        .identity_chirho(),
                    released_chirho.winner_term_chirho,
                    &released_chirho.held_signer_chirho,
                ),
                &released_chirho.adopted_ref_chirho,
            );
            assert_eq!(
                outcome_chirho,
                Ok(Gd7WriteRestorationOutcomeChirho::RestoredChirho),
                "MEASURED at 3be78ffc, and RULED into CHAIN-CERT-1 rather than left unnoticed: the \
                 signature binds the certificate to its signer and the stored checkpoint, not to a \
                 measured population"
            );
            let confirmation_chirho = load_verified_write_restoration_confirmation_chirho(
                &released_chirho.storage_chirho,
                &released_chirho.held_signer_chirho,
                &released_chirho.group_digest_chirho,
                &released_chirho.adopted_ref_chirho,
            )
            .expect("the confirmation reloads")
            .expect("the confirmation is present");
            assert_eq!(
                confirmation_chirho
                    .verified_closed_population_total_chirho()
                    .expect("no overflow"),
                0,
                "the durable audit artifact attests a closed population of ZERO — the exact value \
                 CHAIN-CERT-1 must make impossible to assert without an enumerated population"
            );
        },
    );
}
