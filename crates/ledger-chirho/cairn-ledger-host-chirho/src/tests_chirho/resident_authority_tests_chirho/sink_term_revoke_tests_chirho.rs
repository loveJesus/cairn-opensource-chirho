// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Arms for the one lawful mid-life sink-cell advance.
//!
//! The observation is REAL — imported through the signature-verifying witness reader, not
//! hand-built — so the term these arms accept is the term a genuine cross-host winner witness
//! carries. The adopted-cut and freshness bindings are exercised against the pure authorization
//! decision, and the durable advance is exercised end to end against a stored, held-signed
//! `AdoptedHeldChirho` checkpoint bound to that same observation.

use super::super::reconciliation_witness_tests_chirho::{
    digest_chirho, empty_verified_losing_tail_chirho, held_winner_import_fixture_chirho,
    open_storage_chirho, FakeGd7ControlSignerChirho, FakeWinnerLedgerSignerChirho,
};
use crate::reconciliation_chirho::sink_term_fence_chirho::read_sink_term_fence_chirho;
use crate::reconciliation_chirho::{
    AuthenticatedGd7DeposedForkObservationChirho, Gd7ReconciliationCheckpointChirho,
    Gd7ReconciliationCheckpointStateChirho, Gd7ReconciliationPhaseChirho,
    Gd7WinnerWitnessReaderChirho, GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO,
};
use crate::resident_authority_chirho::sink_term_revoke_chirho::{
    authorize_lawful_sink_term_advance_chirho, release_converged_reconciliation_hold_chirho,
    revoke_and_accept_new_winner_term_chirho, LawfulSinkTermAdvanceRefusalChirho,
};
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;

/// Import one genuine, signature-verified deposed-fork observation.
fn authenticated_observation_chirho(
    label_chirho: &str,
) -> (
    std::path::PathBuf,
    AuthenticatedGd7DeposedForkObservationChirho,
) {
    let (source_root_chirho, source_storage_chirho) =
        open_storage_chirho(&format!("{label_chirho}-source-chirho"));
    let (held_root_chirho, held_storage_chirho) =
        open_storage_chirho(&format!("{label_chirho}-held-chirho"));
    let control_signer_chirho = FakeGd7ControlSignerChirho::new_chirho(digest_chirho('a'), 0x31);
    let ledger_signer_chirho = FakeWinnerLedgerSignerChirho::new_chirho(0x32);
    let losing_tail_chirho = empty_verified_losing_tail_chirho(
        &held_storage_chirho,
        &ledger_signer_chirho,
        "valid-chirho",
    );
    let fixture_chirho = held_winner_import_fixture_chirho(
        &source_storage_chirho,
        &control_signer_chirho,
        &ledger_signer_chirho,
        &losing_tail_chirho,
    );
    let reader_chirho = Gd7WinnerWitnessReaderChirho::new_chirho(
        &held_storage_chirho,
        &control_signer_chirho,
        &ledger_signer_chirho,
    );
    let observation_chirho = reader_chirho
        .import_authenticated_deposed_fork_observation_chirho(
            &fixture_chirho.identity_chirho,
            &fixture_chirho.index_bytes_chirho,
            &fixture_chirho.witness_bytes_chirho,
            &losing_tail_chirho,
        )
        .expect("import the genuine authenticated observation");
    drop(source_root_chirho);
    (held_root_chirho, observation_chirho)
}

/// An adopted cut bound to this exact observation. Built directly because the PURE decision under
/// test takes an already-authenticated checkpoint; authentication is the wrapper's job and is
/// exercised separately by the end-to-end arm.
fn adopted_cut_for_chirho(
    observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
) -> Gd7ReconciliationCheckpointChirho {
    Gd7ReconciliationCheckpointChirho {
        schema_chirho: GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO.to_owned(),
        identity_chirho: observation_chirho.identity_chirho().clone(),
        winner_fork_witness_object_digest_chirho: observation_chirho
            .winner_fork_witness_chirho()
            .object_digest_chirho()
            .to_owned(),
        state_chirho: Gd7ReconciliationCheckpointStateChirho {
            phase_chirho: Gd7ReconciliationPhaseChirho::AdoptedHeldChirho,
            transition_seq_chirho: 4,
            previous_checkpoint_ref_chirho: Some(digest_chirho('c')),
            manifest_head_ref_chirho: Some(digest_chirho('d')),
            manifest_page_count_chirho: 1,
            manifest_record_count_chirho: 1,
            plan_head_ref_chirho: Some(digest_chirho('e')),
            plan_page_count_chirho: 1,
            sealed_plan_ref_chirho: Some(digest_chirho('e')),
            effect_obligation_count_chirho: 0,
            cursor_object_ref_chirho: None,
            adoption_binding_chirho: Some(
                super::super::resident_adoption_tests_chirho::adoption_binding_chirho(
                    &digest_chirho('e'),
                ),
            ),
        },
        key_id_chirho: "held-node-chirho".to_owned(),
        sig_chirho: digest_chirho('f'),
    }
}

#[test]
fn lawful_advance_authorizes_by_term_values_and_refuses_every_broken_binding_chirho() {
    let (_held_root_chirho, observation_chirho) =
        authenticated_observation_chirho("lawful-advance-bindings");
    let identity_chirho = observation_chirho.identity_chirho().clone();
    let group_digest_chirho = identity_chirho.consistency_group_digest_chirho.clone();
    let winner_term_chirho = identity_chirho.winner_term_chirho;
    let adopted_cut_chirho = adopted_cut_for_chirho(&observation_chirho);

    // CONTROL: the untampered set authorizes, and it authorizes the WITNESS's term by value — not a
    // term any caller named. Every refusal below is therefore caused by its own mutation.
    assert_eq!(
        authorize_lawful_sink_term_advance_chirho(
            &group_digest_chirho,
            &observation_chirho,
            &adopted_cut_chirho,
            winner_term_chirho,
        ),
        Ok(winner_term_chirho),
        "control: real witness + adopted cut + matching local term authorizes the witness's term"
    );

    // FRESHNESS, both directions. Below: this node is not the live writer at the winner's term.
    assert_eq!(
        authorize_lawful_sink_term_advance_chirho(
            &group_digest_chirho,
            &observation_chirho,
            &adopted_cut_chirho,
            winner_term_chirho - 1,
        ),
        Err(
            LawfulSinkTermAdvanceRefusalChirho::LocalTermBehindWitnessChirho {
                local_term_chirho: winner_term_chirho - 1,
                witness_winner_term_chirho: winner_term_chirho,
            }
        )
    );
    // Above: the cluster has elected past this witness, so accepting it installs a superseded
    // winner. This is the arm that makes the binding an EQUALITY rather than a floor.
    assert_eq!(
        authorize_lawful_sink_term_advance_chirho(
            &group_digest_chirho,
            &observation_chirho,
            &adopted_cut_chirho,
            winner_term_chirho + 1,
        ),
        Err(
            LawfulSinkTermAdvanceRefusalChirho::LocalTermAheadOfWitnessChirho {
                local_term_chirho: winner_term_chirho + 1,
                witness_winner_term_chirho: winner_term_chirho,
            }
        )
    );

    // FOREIGN GROUP: a genuine observation for another group may not advance this group's cell.
    let foreign_group_digest_chirho = digest_chirho('7');
    assert_eq!(
        authorize_lawful_sink_term_advance_chirho(
            &foreign_group_digest_chirho,
            &observation_chirho,
            &adopted_cut_chirho,
            winner_term_chirho,
        ),
        Err(LawfulSinkTermAdvanceRefusalChirho::ForeignGroupChirho {
            expected_group_digest_chirho: foreign_group_digest_chirho,
            observed_group_digest_chirho: group_digest_chirho.clone(),
        })
    );

    // ADOPTED CUT bindings, each broken on its own.
    let mut foreign_identity_cut_chirho = adopted_cut_chirho.clone();
    foreign_identity_cut_chirho
        .identity_chirho
        .winner_node_chirho = "some-other-winner-chirho".to_owned();
    assert_eq!(
        authorize_lawful_sink_term_advance_chirho(
            &group_digest_chirho,
            &observation_chirho,
            &foreign_identity_cut_chirho,
            winner_term_chirho,
        ),
        Err(LawfulSinkTermAdvanceRefusalChirho::AdoptedCutIdentityMismatchChirho)
    );

    let mut foreign_witness_cut_chirho = adopted_cut_chirho.clone();
    foreign_witness_cut_chirho.winner_fork_witness_object_digest_chirho = digest_chirho('8');
    assert_eq!(
        authorize_lawful_sink_term_advance_chirho(
            &group_digest_chirho,
            &observation_chirho,
            &foreign_witness_cut_chirho,
            winner_term_chirho,
        ),
        Err(
            LawfulSinkTermAdvanceRefusalChirho::AdoptedCutWitnessMismatchChirho {
                checkpoint_witness_digest_chirho: digest_chirho('8'),
                observed_witness_digest_chirho: observation_chirho
                    .winner_fork_witness_chirho()
                    .object_digest_chirho()
                    .to_owned(),
            }
        )
    );

    for unadopted_phase_chirho in [
        Gd7ReconciliationPhaseChirho::ObservedHeldChirho,
        Gd7ReconciliationPhaseChirho::ManifestingChirho,
        Gd7ReconciliationPhaseChirho::PlanSealedChirho,
    ] {
        let mut unadopted_cut_chirho = adopted_cut_chirho.clone();
        unadopted_cut_chirho.state_chirho.phase_chirho = unadopted_phase_chirho;
        assert_eq!(
            authorize_lawful_sink_term_advance_chirho(
                &group_digest_chirho,
                &observation_chirho,
                &unadopted_cut_chirho,
                winner_term_chirho,
            ),
            Err(
                LawfulSinkTermAdvanceRefusalChirho::AdoptedCutNotAdoptedChirho {
                    phase_chirho: unadopted_phase_chirho,
                }
            ),
            "an unadopted cut must not authorize an advance"
        );
    }

    let mut unbound_cut_chirho = adopted_cut_chirho.clone();
    unbound_cut_chirho.state_chirho.adoption_binding_chirho = None;
    assert_eq!(
        authorize_lawful_sink_term_advance_chirho(
            &group_digest_chirho,
            &observation_chirho,
            &unbound_cut_chirho,
            winner_term_chirho,
        ),
        Err(LawfulSinkTermAdvanceRefusalChirho::AdoptedCutMissingAdoptionBindingChirho)
    );
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn a_mid_life_term_bump_without_the_revoke_operation_still_strands_chirho() {
    // BOX 7. The lawful advance now EXISTS; this arm proves its mere existence does not unstrand
    // anything. The real operation is INVOKED with evidence it cannot authenticate, and it must
    // refuse by name while leaving the durable cell exactly where birth put it — the fail-closed
    // placement the module documents, where every check runs BEFORE the write.
    // STRAND-1 pins the complementary half: that the compensation append never self-advances.
    let (_held_root_chirho, observation_chirho) =
        authenticated_observation_chirho("box7-mid-life-strand");
    let verifier_chirho = FakeGd7ControlSignerChirho::new_chirho(digest_chirho('a'), 0x31);
    super::with_bound_resident_fixture_chirho(
        "sink-term-revoke-box7-strand",
        |root_chirho,
         group_chirho,
         node_chirho,
         _ports_chirho,
         _journal_chirho,
         _cluster_chirho| {
            let group_digest_chirho =
                cairn_writer_head_chirho::writer_head_chirho::consistency_group_digest_chirho(
                    group_chirho,
                )
                .unwrap();
            let elector_chirho = super::warm_single_node_elector_chirho(node_chirho, group_chirho);
            let handle_chirho = elector_chirho.local_append_authority_handle_chirho();
            let generation_guard_chirho = handle_chirho
                .try_acquire_chirho()
                .expect("seal the live local authority generation");

            super::sink_term_lifecycle_tests_chirho::under_resident_writer_lock_chirho(
                root_chirho,
                |writer_lock_guard_chirho| {
                    let cell_before_chirho =
                        read_sink_term_fence_chirho(writer_lock_guard_chirho, &group_digest_chirho)
                            .expect("read the birthed cell")
                            .expect("resident birth created the cell");

                    // Matched rather than `expect_err`: the witness type carries no derives, by
                    // the same design as the birth witness, and a test must not weaken that.
                    let refusal_chirho = match revoke_and_accept_new_winner_term_chirho(
                        writer_lock_guard_chirho,
                        group_chirho,
                        &observation_chirho,
                        &digest_chirho('b'),
                        &verifier_chirho,
                        &generation_guard_chirho,
                    ) {
                        Ok(_advanced_chirho) => {
                            panic!("an unauthenticated adopted cut must not advance the cell")
                        }
                        Err(refusal_chirho) => refusal_chirho,
                    };
                    assert!(
                        matches!(
                            refusal_chirho,
                            LawfulSinkTermAdvanceRefusalChirho::AdoptedCutUnauthenticatedChirho { .. }
                        ),
                        "expected an unauthenticated-cut refusal, got {refusal_chirho:?}"
                    );

                    assert_eq!(
                        read_sink_term_fence_chirho(writer_lock_guard_chirho, &group_digest_chirho)
                            .expect("re-read the cell")
                            .expect("the cell still exists"),
                        cell_before_chirho,
                        "a refused advance must leave the accepted term exactly where it was"
                    );
                },
            );
        },
    );
}

/// The four-commit AdoptedHeld chain, built with `new_authenticated_chirho` so the store's witness
/// digest is the OBSERVATION's real one rather than `new_chirho`'s `"9".repeat(64)` placeholder.
///
/// Returns the adopted checkpoint ref. This is precondition 1's exact gap: the existing adoption
/// helper binds a placeholder witness, so a cut it produced could never match a real observation.
fn install_adopted_cut_bound_to_observation_chirho(
    storage_chirho: &crate::storage_chirho::FsLedgerStorageChirho,
    signer_chirho: &FakeGd7ControlSignerChirho,
    observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
) -> String {
    let store_chirho =
        crate::reconciliation_chirho::Gd7ReconciliationStoreChirho::new_authenticated_chirho(
            storage_chirho,
            signer_chirho,
            observation_chirho.identity_chirho().clone(),
            observation_chirho
                .winner_fork_witness_chirho()
                .object_digest_chirho()
                .to_owned(),
        )
        .expect("the signer's key id equals the identity's held node, so the store authenticates");
    let observed_chirho = store_chirho
        .commit_checkpoint_chirho(None, observed_held_state_for_arm_chirho())
        .expect("commit the observed-held checkpoint");
    let manifesting_chirho = store_chirho
        .commit_checkpoint_chirho(
            Some(&observed_chirho.checkpoint_ref_chirho),
            manifesting_state_for_arm_chirho(&observed_chirho.checkpoint_ref_chirho),
        )
        .expect("commit the manifesting checkpoint");
    let sealed_chirho = store_chirho
        .commit_checkpoint_chirho(
            Some(&manifesting_chirho.checkpoint_ref_chirho),
            sealed_state_for_arm_chirho(&manifesting_chirho.checkpoint_ref_chirho),
        )
        .expect("commit the plan-sealed checkpoint");
    let adopted_chirho = store_chirho
        .commit_adopted_held_checkpoint_chirho(
            &sealed_chirho.checkpoint_ref_chirho,
            super::super::resident_adoption_tests_chirho::adoption_binding_chirho(
                &sealed_chirho.checkpoint_ref_chirho,
            ),
        )
        .expect("commit the adopted-held checkpoint");
    adopted_chirho.checkpoint_ref_chirho
}

fn observed_held_state_for_arm_chirho() -> Gd7ReconciliationCheckpointStateChirho {
    Gd7ReconciliationCheckpointStateChirho {
        phase_chirho: Gd7ReconciliationPhaseChirho::ObservedHeldChirho,
        transition_seq_chirho: 0,
        previous_checkpoint_ref_chirho: None,
        manifest_head_ref_chirho: None,
        manifest_page_count_chirho: 0,
        manifest_record_count_chirho: 0,
        plan_head_ref_chirho: None,
        plan_page_count_chirho: 0,
        sealed_plan_ref_chirho: None,
        effect_obligation_count_chirho: 0,
        cursor_object_ref_chirho: None,
        adoption_binding_chirho: None,
    }
}

fn manifesting_state_for_arm_chirho(
    previous_ref_chirho: &str,
) -> Gd7ReconciliationCheckpointStateChirho {
    Gd7ReconciliationCheckpointStateChirho {
        phase_chirho: Gd7ReconciliationPhaseChirho::ManifestingChirho,
        transition_seq_chirho: 1,
        previous_checkpoint_ref_chirho: Some(previous_ref_chirho.to_owned()),
        manifest_head_ref_chirho: Some(digest_chirho('7')),
        manifest_page_count_chirho: 1,
        manifest_record_count_chirho: 3,
        plan_head_ref_chirho: None,
        plan_page_count_chirho: 0,
        sealed_plan_ref_chirho: None,
        effect_obligation_count_chirho: 0,
        cursor_object_ref_chirho: None,
        adoption_binding_chirho: None,
    }
}

fn sealed_state_for_arm_chirho(
    previous_ref_chirho: &str,
) -> Gd7ReconciliationCheckpointStateChirho {
    Gd7ReconciliationCheckpointStateChirho {
        phase_chirho: Gd7ReconciliationPhaseChirho::PlanSealedChirho,
        transition_seq_chirho: 2,
        previous_checkpoint_ref_chirho: Some(previous_ref_chirho.to_owned()),
        manifest_head_ref_chirho: Some(digest_chirho('7')),
        manifest_page_count_chirho: 1,
        manifest_record_count_chirho: 3,
        plan_head_ref_chirho: Some(digest_chirho('8')),
        plan_page_count_chirho: 1,
        sealed_plan_ref_chirho: Some(digest_chirho('8')),
        effect_obligation_count_chirho: 2,
        cursor_object_ref_chirho: None,
        adoption_binding_chirho: None,
    }
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn a_real_adopted_cut_bound_to_a_real_observation_advances_the_durable_cell_chirho() {
    // PRECONDITION 1, and the single biggest gap the D2 land recorded: nothing had ever driven a
    // SUCCESSFUL durable advance through the whole operation. The success path was proven only at
    // the pure decision (by term values); the composition of that decision with the durable write,
    // against a REAL stored AdoptedHeld cut bound to a REAL imported observation, was unproven.
    //
    // Everything here is genuine: the observation is imported through the signature-verifying
    // witness reader, and the cut is committed through the real store with the observation's own
    // witness digest — so `load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho` inside
    // the operation must actually authenticate it rather than be handed a value.
    let (held_root_chirho, observation_chirho) =
        authenticated_observation_chirho("lawful-advance-composition");
    let identity_chirho = observation_chirho.identity_chirho().clone();
    let witness_term_chirho = identity_chirho.winner_term_chirho;

    // The store signer's key id MUST equal the identity's held node, or `new_authenticated_chirho`
    // refuses with SignerKeyMismatchChirho. This is the binding constraint precondition 1 named.
    let held_signer_chirho =
        FakeGd7ControlSignerChirho::new_chirho(identity_chirho.held_node_chirho.clone(), 0x41);
    let storage_chirho = crate::storage_chirho::FsLedgerStorageChirho::open_existing_chirho(
        held_root_chirho.as_path(),
    )
    .expect("open the held root that received the imported observation");
    let adopted_ref_chirho = install_adopted_cut_bound_to_observation_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &observation_chirho,
    );

    let group_chirho =
        cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho::TenantChirho {
            tenant_id_chirho: "gd7-held-winner-import-tenant-chirho".to_owned(),
        };
    let group_digest_chirho =
        cairn_writer_head_chirho::writer_head_chirho::consistency_group_digest_chirho(
            &group_chirho,
        )
        .expect("the import fixture's group digests");
    assert_eq!(
        group_digest_chirho, identity_chirho.consistency_group_digest_chirho,
        "the arm must drive the SAME group the observation names, or it would prove only the foreign-group refusal"
    );

    let node_chirho = cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho(
        identity_chirho.held_node_chirho.clone(),
    );
    let elector_chirho = super::warm_single_node_elector_chirho(&node_chirho, &group_chirho);
    let handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    let generation_guard_chirho = handle_chirho
        .try_acquire_chirho()
        .expect("seal the live local authority generation");
    assert_eq!(
        generation_guard_chirho.published_raft_term_chirho(),
        witness_term_chirho,
        "FRESHNESS is an equality: this arm is only a success arm if the local published term \
         equals the witness's winner term. If this fires, the fixture's terms drifted apart and \
         the arm below would be measuring a refusal, not an advance."
    );

    super::sink_term_lifecycle_tests_chirho::under_resident_writer_lock_chirho(
        held_root_chirho.as_path(),
        |writer_lock_guard_chirho| {
            // Birth the cell BELOW the witness term, so the advance has somewhere to move to.
            crate::reconciliation_chirho::sink_term_fence_chirho::create_sink_term_fence_at_birth_chirho(
                writer_lock_guard_chirho,
                &group_digest_chirho,
                witness_term_chirho - 1,
            )
            .expect("birth the sink cell one term behind the witness");

            let advanced_chirho = revoke_and_accept_new_winner_term_chirho(
                writer_lock_guard_chirho,
                &group_chirho,
                &observation_chirho,
                &adopted_ref_chirho,
                &held_signer_chirho,
                &generation_guard_chirho,
            )
            .expect("a real adopted cut bound to a real observation must advance the cell");

            assert_eq!(
                advanced_chirho.accepted_term_chirho(),
                witness_term_chirho,
                "the advance accepts the WITNESS's term, by value"
            );
            assert_eq!(
                advanced_chirho.group_digest_chirho(),
                group_digest_chirho,
                "the advance reports the group it actually moved"
            );

            // The DURABLE cell moved — the half the pure decision cannot prove.
            assert_eq!(
                read_sink_term_fence_chirho(writer_lock_guard_chirho, &group_digest_chirho)
                    .expect("re-read the cell")
                    .expect("the cell exists")
                    .highest_accepted_winner_term_chirho,
                witness_term_chirho,
                "the durable accepted term must be the witness's term after a lawful advance"
            );
        },
    );
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn the_adopted_cut_that_authorizes_the_advance_is_itself_an_active_hold_chirho() {
    // MEASUREMENT, not a pin of desired behavior. The map's finding 0 established that a resident
    // append is blocked by MERE PATH PRESENCE of the group active-head. This arm asks the question
    // that decides whether B3a's wire can be demonstrated end to end: does the AdoptedHeld cut that
    // AUTHORIZES the lawful advance also constitute the hold that BLOCKS the append the advance
    // exists to unlock?
    //
    // If it does, then advance-then-append is not reachable in one brick: D3's release (B3c) is
    // the step that lifts the barrier, and any "the append now succeeds" arm written before it
    // would be measuring something other than what it claims.
    let (held_root_chirho, observation_chirho) =
        authenticated_observation_chirho("adopted-cut-is-a-hold");
    let identity_chirho = observation_chirho.identity_chirho().clone();
    let held_signer_chirho =
        FakeGd7ControlSignerChirho::new_chirho(identity_chirho.held_node_chirho.clone(), 0x41);
    let storage_chirho = crate::storage_chirho::FsLedgerStorageChirho::open_existing_chirho(
        held_root_chirho.as_path(),
    )
    .expect("open the held root");

    assert!(
        !crate::reconciliation_chirho::gd7_reconciliation_group_has_any_active_hold_chirho(
            &storage_chirho,
            &identity_chirho.consistency_group_digest_chirho,
        )
        .expect("probe the hold predicate before any checkpoint exists"),
        "control: with no reconciliation installed the group must NOT be held, or the assertion \
         below would be true no matter what the adoption did.\n\
         \n\
         IF THIS CONTROL IS WHAT WENT RED, THIS IS NOT RELEASE PROGRESS. It means something \
         installed a group active-head before this fixture adopted anything — a contaminated \
         fixture. The measurement below would then be TRUE-BY-CONSTRUCTION and would prove \
         nothing, so read a red here as an instrument fault, never as evidence about the \
         release. Find what wrote the head before fixing anything else."
    );

    let adopted_ref_chirho = install_adopted_cut_bound_to_observation_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &observation_chirho,
    );

    assert!(
        crate::reconciliation_chirho::gd7_reconciliation_group_has_any_active_hold_chirho(
            &storage_chirho,
            &identity_chirho.consistency_group_digest_chirho,
        )
        .expect("probe the hold predicate after adoption"),
        "MEASURED: the AdoptedHeld cut leaves the group active-head in place, so the evidence that \
         authorizes the lawful advance is simultaneously the barrier that refuses every resident \
         append with Gd7ReconciliationHoldActiveChirho. advance-then-append cannot be demonstrated \
         until D3's release supersedes that head.\n\
         \n\
         IF THIS ASSERT IS WHAT WENT RED, THAT IS THE INTENDED FLIP, NOT A DEFECT. B3c's \
         ref-supersede release is designed to make this false: adoption no longer leaves the group \
         held, so the barrier is lifted and the append the advance unlocks becomes reachable. Do \
         NOT re-assert the old behaviour. RETARGET this arm to pin the RELEASED shape:\n\
         \n\
           1. held BEFORE the release runs (this arm's current measurement, kept as the setup),\n\
           2. NOT held after it,\n\
           3. and the PRIOR head object still readable and byte-unchanged.\n\
         \n\
         Item 3 is the one that is easy to drop and the one that matters most. R-b was re-ruled \
         A-AS-REF-MOVE: release SUPERSEDES the ref and RETAINS the prior object immutable. So \
         `not held` must never be allowed to mean `deleted` — an arm that checks only the \
         predicate would pass just as happily for an implementation that erased the evidence, \
         which is precisely the outcome D5 clauses 9/10 forbid.\n\
         \n\
         Also retarget the module header and the two comments above, which still describe \
         advance-then-append as unreachable."
    );

    let head_path_chirho = crate::reconciliation_chirho::gd7_reconciliation_group_head_path_chirho(
        &identity_chirho.consistency_group_digest_chirho,
    )
    .expect("derive active head path");
    let head_before_chirho = storage_chirho
        .read_all_chirho(&head_path_chirho)
        .expect("read active head before release")
        .expect("active head exists before release");
    let checkpoint_path_chirho =
        crate::reconciliation_chirho::gd7_reconciliation_checkpoint_path_chirho(
            &adopted_ref_chirho,
        )
        .expect("derive retained checkpoint path");
    let checkpoint_before_chirho = storage_chirho
        .read_all_chirho(&checkpoint_path_chirho)
        .expect("read checkpoint before release")
        .expect("checkpoint exists before release");
    let group_chirho =
        cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho::TenantChirho {
            tenant_id_chirho: "gd7-held-winner-import-tenant-chirho".to_owned(),
        };
    let convergence_chirho =
        crate::reconciliation_chirho::signed_converged_read_replica_for_release_test_chirho(
            adopted_ref_chirho.clone(),
            &held_signer_chirho,
        );
    super::sink_term_lifecycle_tests_chirho::under_resident_writer_lock_chirho(
        held_root_chirho.as_path(),
        |writer_lock_guard_chirho| {
            release_converged_reconciliation_hold_chirho(
                writer_lock_guard_chirho,
                &group_chirho,
                &adopted_ref_chirho,
                &convergence_chirho,
                &held_signer_chirho,
            )
            .expect("release the exact adopted head");
        },
    );
    assert!(
        !crate::reconciliation_chirho::gd7_reconciliation_group_has_any_active_hold_chirho(
            &storage_chirho,
            &identity_chirho.consistency_group_digest_chirho,
        )
        .expect("probe the hold predicate after release")
    );
    assert!(
        !head_before_chirho.is_empty(),
        "the removed ref had real evidence bytes"
    );
    assert!(
        storage_chirho
            .read_all_chirho(&checkpoint_path_chirho)
            .expect("read retained checkpoint")
            .as_ref()
            .is_some_and(|bytes_chirho| bytes_chirho == &checkpoint_before_chirho),
        "the release supersedes the ref but retains its immutable checkpoint byte-for-byte"
    );
}

/// The release door now VERIFIES the convergence certificate's signature, so a fabricated or
/// tampered certificate cannot lift the reconciliation hold. Before this brick the door consumed the
/// certificate only through its unauthenticated `.checkpoint_ref_chirho()` getter, and the exact v1
/// unsigned fixture below released the hold. This is the money-authority pin for that closed hole.
///
/// MIGRATION PATH: if any fabricated sub-case starts RELEASING (the head goes absent), the signature
/// binding in `release_converged_reconciliation_hold_chirho` regressed — a forged certificate must
/// never supersede an active head. If a sub-case's refusal NAME changes away from
/// `ConvergenceCertificateUnverifiedChirho`, the door started refusing these fixtures for an
/// unrelated reason and this arm stopped measuring the signature binding; read the new name before
/// loosening anything. The POSITIVE CONTROL at the end must keep releasing, or the refusals above
/// are a door that refuses every certificate rather than the signature at work.
#[test]
fn a_fabricated_or_tampered_convergence_certificate_cannot_release_the_hold_chirho() {
    let (held_root_chirho, observation_chirho) =
        authenticated_observation_chirho("fabricated-cert-cannot-release");
    let identity_chirho = observation_chirho.identity_chirho().clone();
    let held_signer_chirho =
        FakeGd7ControlSignerChirho::new_chirho(identity_chirho.held_node_chirho.clone(), 0x41);
    let storage_chirho = crate::storage_chirho::FsLedgerStorageChirho::open_existing_chirho(
        held_root_chirho.as_path(),
    )
    .expect("open the held root");
    let adopted_ref_chirho = install_adopted_cut_bound_to_observation_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &observation_chirho,
    );
    assert!(
        crate::reconciliation_chirho::gd7_reconciliation_group_has_any_active_hold_chirho(
            &storage_chirho,
            &identity_chirho.consistency_group_digest_chirho,
        )
        .expect("probe the hold after adoption"),
        "setup: the adopted cut must leave the group held, or every refusal below measures an empty \
         world"
    );
    let head_path_chirho = crate::reconciliation_chirho::gd7_reconciliation_group_head_path_chirho(
        &identity_chirho.consistency_group_digest_chirho,
    )
    .expect("derive active head path");
    let head_before_chirho = storage_chirho
        .read_all_chirho(&head_path_chirho)
        .expect("read active head before")
        .expect("active head exists before");
    let checkpoint_path_chirho =
        crate::reconciliation_chirho::gd7_reconciliation_checkpoint_path_chirho(
            &adopted_ref_chirho,
        )
        .expect("derive retained checkpoint path");
    let checkpoint_before_chirho = storage_chirho
        .read_all_chirho(&checkpoint_path_chirho)
        .expect("read checkpoint before")
        .expect("checkpoint exists before");
    let group_chirho =
        cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho::TenantChirho {
            tenant_id_chirho: "gd7-held-winner-import-tenant-chirho".to_owned(),
        };

    // A DIFFERENT custody key than the held verifier: a certificate signed by it is well-formed and
    // truly signed, but not by the authority the release door trusts.
    let wrong_signer_chirho =
        FakeGd7ControlSignerChirho::new_chirho(identity_chirho.held_node_chirho.clone(), 0x77);
    // The exact v1 unsigned fixture that released the hold before this brick.
    let v1_unsigned_chirho =
        crate::reconciliation_chirho::converged_read_replica_for_release_test_chirho(
            adopted_ref_chirho.clone(),
        );
    // A real v2 certificate, signed — but by a foreign key.
    let wrong_key_chirho =
        crate::reconciliation_chirho::signed_converged_read_replica_for_release_test_chirho(
            adopted_ref_chirho.clone(),
            &wrong_signer_chirho,
        );
    // A real held-signed v2 certificate whose signed `winner_term_chirho` is then tampered, so the
    // signature no longer covers the bytes: proves the signature binds the fields, not merely a
    // well-formed shape. The `checkpoint_ref_chirho` is untouched, so the door's cheap field-equality
    // check passes and the SIGNATURE is what refuses.
    let honest_chirho =
        crate::reconciliation_chirho::signed_converged_read_replica_for_release_test_chirho(
            adopted_ref_chirho.clone(),
            &held_signer_chirho,
        );
    let mut tampered_value_chirho =
        serde_json::to_value(&honest_chirho).expect("the honest certificate serializes");
    tampered_value_chirho["winner_term_chirho"] = serde_json::json!(999);
    let tampered_field_chirho: crate::reconciliation_chirho::ConvergedReadReplicaChirho =
        serde_json::from_value(tampered_value_chirho)
            .expect("the tampered certificate still deserializes");

    for (label_chirho, fabricated_chirho) in [
        ("v1 unsigned (the exact pre-brick hole)", v1_unsigned_chirho),
        ("v2 signed by a foreign custody key", wrong_key_chirho),
        (
            "v2 held-signed with a tampered signed field",
            tampered_field_chirho,
        ),
    ] {
        super::sink_term_lifecycle_tests_chirho::under_resident_writer_lock_chirho(
            held_root_chirho.as_path(),
            |writer_lock_guard_chirho| {
                let refusal_chirho = release_converged_reconciliation_hold_chirho(
                    writer_lock_guard_chirho,
                    &group_chirho,
                    &adopted_ref_chirho,
                    &fabricated_chirho,
                    &held_signer_chirho,
                )
                .expect_err(&format!(
                    "release must REFUSE a fabricated certificate ({label_chirho}); a success means \
                     the signature binding regressed and a forged certificate lifted the hold"
                ));
                assert!(
                    matches!(
                        refusal_chirho,
                        LawfulSinkTermAdvanceRefusalChirho::ConvergenceCertificateUnverifiedChirho {
                            ..
                        }
                    ),
                    "the refusal must name the certificate-verification barrier ({label_chirho}), \
                     not an unrelated one: {refusal_chirho:?}"
                );
            },
        );
        assert!(
            crate::reconciliation_chirho::gd7_reconciliation_group_has_any_active_hold_chirho(
                &storage_chirho,
                &identity_chirho.consistency_group_digest_chirho,
            )
            .expect("probe the hold after a refused release"),
            "a refused release must leave the hold ACTIVE ({label_chirho})"
        );
        assert_eq!(
            storage_chirho
                .read_all_chirho(&head_path_chirho)
                .expect("read active head after a refused release")
                .as_deref(),
            Some(head_before_chirho.as_slice()),
            "a refused release must leave the active head present and byte-unchanged ({label_chirho})"
        );
    }

    // POSITIVE CONTROL: the honest held-signed certificate DOES release, so the refusals above are
    // the signature binding at work, not a door that refuses every certificate.
    let honest_release_chirho =
        crate::reconciliation_chirho::signed_converged_read_replica_for_release_test_chirho(
            adopted_ref_chirho.clone(),
            &held_signer_chirho,
        );
    super::sink_term_lifecycle_tests_chirho::under_resident_writer_lock_chirho(
        held_root_chirho.as_path(),
        |writer_lock_guard_chirho| {
            release_converged_reconciliation_hold_chirho(
                writer_lock_guard_chirho,
                &group_chirho,
                &adopted_ref_chirho,
                &honest_release_chirho,
                &held_signer_chirho,
            )
            .expect("the honest held-signed certificate releases the exact adopted head");
        },
    );
    assert!(
        !crate::reconciliation_chirho::gd7_reconciliation_group_has_any_active_hold_chirho(
            &storage_chirho,
            &identity_chirho.consistency_group_digest_chirho,
        )
        .expect("probe the hold after the honest release"),
        "the honest certificate supersedes the head"
    );
    assert!(
        storage_chirho
            .read_all_chirho(&checkpoint_path_chirho)
            .expect("read retained checkpoint")
            .as_ref()
            .is_some_and(|bytes_chirho| bytes_chirho == &checkpoint_before_chirho),
        "release supersedes the ref but retains the immutable checkpoint byte-for-byte"
    );
}
