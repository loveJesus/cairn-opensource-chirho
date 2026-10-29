// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use stateright::{Checker, HasDiscoveries};
use std::collections::BTreeSet;

fn all_laws_model_chirho() -> ModelGd7Chirho {
    ModelGd7Chirho {
        hold_on_observation_law_chirho: true,
        exact_obligation_law_chirho: true,
        authoritative_integrity_law_chirho: true,
        evidence_retention_law_chirho: true,
        winner_authorization_law_chirho: true,
        compensation_idempotency_law_chirho: true,
        compensation_conservation_law_chirho: true,
        crash_progress_law_chirho: true,
        complete_only_when_reconciled_law_chirho: true,
        manual_effect_chirho: None,
    }
}

fn all_gd78_laws_model_chirho() -> ModelGd78Chirho {
    ModelGd78Chirho {
        manifest_membership_law_chirho: true,
        constructed_origin_law_chirho: true,
        deserialized_origin_law_chirho: true,
        foreign_origin_law_chirho: true,
        sink_term_fence_law_chirho: true,
        sink_term_persistence_law_chirho: true,
        compensation_lineage_law_chirho: true,
        definite_release_law_chirho: true,
        ignored_identity_coordinate_chirho: None,
    }
}

fn report_counts_chirho(label_chirho: &str, checker_chirho: &impl Checker<ModelGd7Chirho>) {
    println!(
        "[model-gd7:{}] unique_states={} generated={} max_depth={}",
        label_chirho,
        checker_chirho.unique_state_count(),
        checker_chirho.state_count(),
        checker_chirho.max_depth(),
    );
}

fn report_gd78_counts_chirho(label_chirho: &str, checker_chirho: &impl Checker<ModelGd78Chirho>) {
    println!(
        "[model-gd7-8:{}] unique_states={} generated={} max_depth={}",
        label_chirho,
        checker_chirho.unique_state_count(),
        checker_chirho.state_count(),
        checker_chirho.max_depth(),
    );
}

fn assert_mutation_reddens_chirho(model_chirho: ModelGd7Chirho, target_chirho: &'static str) {
    let checker_chirho = model_chirho
        .checker()
        .finish_when(HasDiscoveries::AnyOf(BTreeSet::from([target_chirho])))
        .spawn_bfs()
        .join();
    report_counts_chirho(target_chirho, &checker_chirho);
    let discovery_chirho = checker_chirho.discovery(target_chirho);
    assert!(
        discovery_chirho.is_some(),
        "mutation must redden {target_chirho}"
    );
    if let Some(path_chirho) = discovery_chirho {
        println!(
            "  [{target_chirho}] violating state: {:?}",
            path_chirho.last_state()
        );
        let actions_chirho = path_chirho.into_actions();
        println!(
            "  [{target_chirho}] {} action(s) to violation: {:?}",
            actions_chirho.len(),
            actions_chirho
        );
    }
}

fn assert_gd78_mutation_reddens_chirho(model_chirho: ModelGd78Chirho, target_chirho: &'static str) {
    let control_chirho = match target_chirho {
        "gd7-8-manifest-membership-bound-chirho" => {
            "gd7-8-not-in-manifest-refusal-reachable-chirho"
        }
        "gd7-8-constructed-obligation-refused-chirho" => {
            "gd7-8-constructed-current-signed-refusal-reachable-chirho"
        }
        "gd7-8-deserialized-obligation-refused-chirho" => {
            "gd7-8-deserialized-current-signed-refusal-reachable-chirho"
        }
        "gd7-8-foreign-obligation-refused-after-current-signature-chirho" => {
            "gd7-8-foreign-current-signed-refusal-reachable-chirho"
        }
        "gd7-8-revoked-barrier-zero-side-effects-chirho" => {
            "gd7-8-revoked-consumption-refused-reachable-chirho"
        }
        "gd7-8-sink-highest-term-survives-restart-chirho" => {
            "gd7-8-restarted-sink-retains-revocation-reachable-chirho"
        }
        "gd7-8-compensation-of-compensation-not-skipped-chirho" => {
            "gd7-8-compensation-of-compensation-consumed-reachable-chirho"
        }
        "gd7-8-definite-no-effect-release-is-not-a-hold-chirho" => {
            "gd7-8-definite-no-effect-release-reachable-chirho"
        }
        _ => "gd7-8-forward-compensation-consumed-reachable-chirho",
    };
    let control_checker_chirho = all_gd78_laws_model_chirho()
        .checker()
        .finish_when(HasDiscoveries::AnyOf(BTreeSet::from([control_chirho])))
        .spawn_bfs()
        .join();
    assert!(
        control_checker_chirho.discovery(control_chirho).is_some(),
        "lawful control must reach {control_chirho} before testing mutation {target_chirho}"
    );

    let checker_chirho = model_chirho
        .checker()
        .finish_when(HasDiscoveries::AnyOf(BTreeSet::from([target_chirho])))
        .spawn_bfs()
        .join();
    report_gd78_counts_chirho(target_chirho, &checker_chirho);
    let discovery_chirho = checker_chirho.discovery(target_chirho);
    assert!(
        discovery_chirho.is_some(),
        "GD7-8 mutation must reach and redden {target_chirho}"
    );
    if let Some(path_chirho) = discovery_chirho {
        println!(
            "  [{target_chirho}] violating state: {:?}",
            path_chirho.last_state()
        );
        let actions_chirho = path_chirho.into_actions();
        println!(
            "  [{target_chirho}] {} action(s) to violation: {:?}",
            actions_chirho.len(),
            actions_chirho
        );
    }
}

#[test]
fn gd7_reconciliation_holds_exhaustively_chirho() {
    let checker_chirho = all_laws_model_chirho().checker().spawn_bfs().join();
    report_counts_chirho("joined-reconciliation", &checker_chirho);
    checker_chirho.assert_properties();
}

#[test]
fn manual_inverse_gap_stays_held_chirho() {
    let checker_chirho = ModelGd7Chirho {
        manual_effect_chirho: Some(0),
        ..all_laws_model_chirho()
    }
    .checker()
    .spawn_bfs()
    .join();
    report_counts_chirho("manual-hold", &checker_chirho);
    checker_chirho.assert_properties();
}

#[test]
fn hold_bypass_makes_gd7_5_red_chirho() {
    assert_mutation_reddens_chirho(
        ModelGd7Chirho {
            hold_on_observation_law_chirho: false,
            ..all_laws_model_chirho()
        },
        "gd7-5-no-partial-authority-chirho",
    );
}

#[test]
fn omitted_effect_obligation_makes_gd7_2_red_chirho() {
    assert_mutation_reddens_chirho(
        ModelGd7Chirho {
            exact_obligation_law_chirho: false,
            ..all_laws_model_chirho()
        },
        "gd7-2-exact-losing-obligations-chirho",
    );
}

#[test]
fn winner_branch_rewrite_makes_gd7_1_red_chirho() {
    assert_mutation_reddens_chirho(
        ModelGd7Chirho {
            authoritative_integrity_law_chirho: false,
            ..all_laws_model_chirho()
        },
        "gd7-1-authoritative-branch-immutable-chirho",
    );
}

#[test]
fn dropping_losing_evidence_makes_gd7_6_red_chirho() {
    assert_mutation_reddens_chirho(
        ModelGd7Chirho {
            evidence_retention_law_chirho: false,
            ..all_laws_model_chirho()
        },
        "gd7-6-evidence-retention-and-convergence-chirho",
    );
}

#[test]
fn deposed_compensation_authority_makes_gd7_4_red_chirho() {
    assert_mutation_reddens_chirho(
        ModelGd7Chirho {
            winner_authorization_law_chirho: false,
            ..all_laws_model_chirho()
        },
        "gd7-4-consume-once-winner-authorization-chirho",
    );
}

#[test]
fn duplicate_compensation_makes_gd7_4_red_chirho() {
    assert_mutation_reddens_chirho(
        ModelGd7Chirho {
            compensation_idempotency_law_chirho: false,
            ..all_laws_model_chirho()
        },
        "gd7-4-consume-once-winner-authorization-chirho",
    );
}

#[test]
fn compensation_without_inverse_delta_makes_gd7_3_red_chirho() {
    assert_mutation_reddens_chirho(
        ModelGd7Chirho {
            compensation_conservation_law_chirho: false,
            ..all_laws_model_chirho()
        },
        "gd7-3-conservation-through-reconciliation-chirho",
    );
}

#[test]
fn crash_forgetting_receipt_makes_progress_red_chirho() {
    assert_mutation_reddens_chirho(
        ModelGd7Chirho {
            crash_progress_law_chirho: false,
            ..all_laws_model_chirho()
        },
        "gd7-crash-progress-is-durable-chirho",
    );
}

#[test]
fn early_completion_makes_gd7_6_red_chirho() {
    assert_mutation_reddens_chirho(
        ModelGd7Chirho {
            complete_only_when_reconciled_law_chirho: false,
            ..all_laws_model_chirho()
        },
        "gd7-6-evidence-retention-and-convergence-chirho",
    );
}

#[test]
fn gd7_8_obligation_provenance_holds_exhaustively_chirho() {
    let checker_chirho = all_gd78_laws_model_chirho().checker().spawn_bfs().join();
    report_gd78_counts_chirho("obligation-provenance", &checker_chirho);
    checker_chirho.assert_properties();
}

#[test]
fn nonmember_obligation_acceptance_makes_gd7_8_red_chirho() {
    assert_gd78_mutation_reddens_chirho(
        ModelGd78Chirho {
            manifest_membership_law_chirho: false,
            ..all_gd78_laws_model_chirho()
        },
        "gd7-8-manifest-membership-bound-chirho",
    );
}

#[test]
fn wrong_plan_identity_acceptance_makes_gd7_8_red_chirho() {
    assert_gd78_mutation_reddens_chirho(
        ModelGd78Chirho {
            ignored_identity_coordinate_chirho: Some(
                Gd78IdentityCoordinateChirho::SealedPlanIdentityChirho,
            ),
            ..all_gd78_laws_model_chirho()
        },
        "gd7-8-sealed-plan-identity-bound-chirho",
    );
}

#[test]
fn wrong_winner_reconciliation_term_acceptance_makes_gd7_8_red_chirho() {
    assert_gd78_mutation_reddens_chirho(
        ModelGd78Chirho {
            ignored_identity_coordinate_chirho: Some(
                Gd78IdentityCoordinateChirho::WinnerReconciliationTermChirho,
            ),
            ..all_gd78_laws_model_chirho()
        },
        "gd7-8-winner-reconciliation-term-bound-chirho",
    );
}

#[test]
fn wrong_obligation_kind_acceptance_makes_gd7_8_red_chirho() {
    assert_gd78_mutation_reddens_chirho(
        ModelGd78Chirho {
            ignored_identity_coordinate_chirho: Some(
                Gd78IdentityCoordinateChirho::ObligationKindChirho,
            ),
            ..all_gd78_laws_model_chirho()
        },
        "gd7-8-obligation-kind-bound-chirho",
    );
}

#[test]
fn wrong_effect_lineage_acceptance_makes_gd7_8_red_chirho() {
    assert_gd78_mutation_reddens_chirho(
        ModelGd78Chirho {
            ignored_identity_coordinate_chirho: Some(
                Gd78IdentityCoordinateChirho::EffectLineageChirho,
            ),
            ..all_gd78_laws_model_chirho()
        },
        "gd7-8-effect-lineage-bound-chirho",
    );
}

#[test]
fn wrong_original_effect_key_acceptance_makes_gd7_8_red_chirho() {
    assert_gd78_mutation_reddens_chirho(
        ModelGd78Chirho {
            ignored_identity_coordinate_chirho: Some(
                Gd78IdentityCoordinateChirho::OriginalEffectKeyChirho,
            ),
            ..all_gd78_laws_model_chirho()
        },
        "gd7-8-original-effect-key-bound-chirho",
    );
}

#[test]
fn wrong_terminal_disposition_acceptance_makes_gd7_8_red_chirho() {
    assert_gd78_mutation_reddens_chirho(
        ModelGd78Chirho {
            ignored_identity_coordinate_chirho: Some(
                Gd78IdentityCoordinateChirho::TerminalDispositionChirho,
            ),
            ..all_gd78_laws_model_chirho()
        },
        "gd7-8-terminal-disposition-bound-chirho",
    );
}

#[test]
fn wrong_terminal_marker_acceptance_makes_gd7_8_red_chirho() {
    assert_gd78_mutation_reddens_chirho(
        ModelGd78Chirho {
            ignored_identity_coordinate_chirho: Some(
                Gd78IdentityCoordinateChirho::TerminalMarkerChirho,
            ),
            ..all_gd78_laws_model_chirho()
        },
        "gd7-8-terminal-marker-bound-chirho",
    );
}

#[test]
fn wrong_source_seq_acceptance_makes_gd7_8_red_chirho() {
    assert_gd78_mutation_reddens_chirho(
        ModelGd78Chirho {
            ignored_identity_coordinate_chirho: Some(Gd78IdentityCoordinateChirho::SourceSeqChirho),
            ..all_gd78_laws_model_chirho()
        },
        "gd7-8-source-seq-bound-chirho",
    );
}

#[test]
fn wrong_source_record_digest_acceptance_makes_gd7_8_red_chirho() {
    assert_gd78_mutation_reddens_chirho(
        ModelGd78Chirho {
            ignored_identity_coordinate_chirho: Some(
                Gd78IdentityCoordinateChirho::SourceRecordDigestChirho,
            ),
            ..all_gd78_laws_model_chirho()
        },
        "gd7-8-source-record-digest-bound-chirho",
    );
}

#[test]
fn constructed_obligation_acceptance_makes_gd7_8_red_chirho() {
    assert_gd78_mutation_reddens_chirho(
        ModelGd78Chirho {
            constructed_origin_law_chirho: false,
            ..all_gd78_laws_model_chirho()
        },
        "gd7-8-constructed-obligation-refused-chirho",
    );
}

#[test]
fn deserialized_obligation_acceptance_makes_gd7_8_red_chirho() {
    assert_gd78_mutation_reddens_chirho(
        ModelGd78Chirho {
            deserialized_origin_law_chirho: false,
            ..all_gd78_laws_model_chirho()
        },
        "gd7-8-deserialized-obligation-refused-chirho",
    );
}

#[test]
fn foreign_obligation_current_signature_acceptance_makes_gd7_8_red_chirho() {
    assert_gd78_mutation_reddens_chirho(
        ModelGd78Chirho {
            foreign_origin_law_chirho: false,
            ..all_gd78_laws_model_chirho()
        },
        "gd7-8-foreign-obligation-refused-after-current-signature-chirho",
    );
}

#[test]
fn revoked_barrier_consumption_makes_gd7_8_red_chirho() {
    assert_gd78_mutation_reddens_chirho(
        ModelGd78Chirho {
            sink_term_fence_law_chirho: false,
            ..all_gd78_laws_model_chirho()
        },
        "gd7-8-revoked-barrier-zero-side-effects-chirho",
    );
}

#[test]
fn sink_restart_forgetting_highest_term_makes_gd7_8_red_chirho() {
    assert_gd78_mutation_reddens_chirho(
        ModelGd78Chirho {
            sink_term_persistence_law_chirho: false,
            ..all_gd78_laws_model_chirho()
        },
        "gd7-8-sink-highest-term-survives-restart-chirho",
    );
}

#[test]
fn compensation_of_compensation_skip_makes_gd7_8_red_chirho() {
    assert_gd78_mutation_reddens_chirho(
        ModelGd78Chirho {
            compensation_lineage_law_chirho: false,
            ..all_gd78_laws_model_chirho()
        },
        "gd7-8-compensation-of-compensation-not-skipped-chirho",
    );
}

#[test]
fn definite_no_effect_release_hold_flattening_makes_gd7_8_red_chirho() {
    assert_gd78_mutation_reddens_chirho(
        ModelGd78Chirho {
            definite_release_law_chirho: false,
            ..all_gd78_laws_model_chirho()
        },
        "gd7-8-definite-no-effect-release-is-not-a-hold-chirho",
    );
}
