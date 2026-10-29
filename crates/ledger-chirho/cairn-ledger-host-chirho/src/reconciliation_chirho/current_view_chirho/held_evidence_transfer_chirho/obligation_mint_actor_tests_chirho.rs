// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::reconciliation_chirho::{
    verified_gd7_sealed_plan_obligation_for_test_chirho, Gd7EffectEvidenceReaderPortChirho,
    Gd7EffectLineageChirho, Gd7EffectPlanObligationChirho, Gd7EffectPlanObligationKindChirho,
    Gd7EffectProofPortsChirho, Gd7LosingEffectObligationMintRefusalChirho,
    Gd7LosingEffectObligationSelectorChirho,
};
use crate::resident_authority_chirho::{
    mint_actor_owned_gd7_losing_effect_obligation_with_hooks_for_test_chirho,
    ResidentGd7HeldObligationMintActorPortsChirho, ResidentGd7HeldObligationMintRefusalChirho,
};
use anyhow::Result;
use cairn_effect_commit_chirho::intent_chirho::EffectIntentSignerPortChirho;
use cairn_effect_commit_chirho::terminal_chirho::EffectTerminalSignerPortChirho;
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::record_chirho::EscrowControlChirho;

struct ClosedEffectEvidenceChirho;

impl Gd7EffectEvidenceReaderPortChirho for ClosedEffectEvidenceChirho {
    fn load_intent_line_bounded_chirho(
        &self,
        _intent_ref_chirho: &DigestChirho,
        _maximum_bytes_chirho: usize,
    ) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    fn load_terminal_line_bounded_chirho(
        &self,
        _outcome_ref_chirho: &DigestChirho,
        _maximum_bytes_chirho: usize,
    ) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

struct ClosedIntentVerifierChirho;

impl EffectIntentSignerPortChirho for ClosedIntentVerifierChirho {
    fn sign_chirho(&self, _signed_content_line_chirho: &str) -> Result<String> {
        anyhow::bail!("closed test verifier cannot sign")
    }

    fn key_id_chirho(&self) -> String {
        "gd7-obligation-closed-intent-root-chirho".to_owned()
    }

    fn verify_chirho(&self, _signed_content_line_chirho: &str, _sig_chirho: &str) -> bool {
        false
    }
}

struct ClosedTerminalVerifierChirho;

impl EffectTerminalSignerPortChirho for ClosedTerminalVerifierChirho {
    fn sign_chirho(&self, _signed_content_line_chirho: &str) -> Result<String> {
        anyhow::bail!("closed test verifier cannot sign")
    }

    fn key_id_chirho(&self) -> String {
        "gd7-obligation-closed-terminal-root-chirho".to_owned()
    }

    fn verify_chirho(&self, _signed_content_line_chirho: &str, _sig_chirho: &str) -> bool {
        false
    }
}

#[test]
fn adopted_actor_mints_once_and_retry_moves_no_existing_surface_chirho() {
    with_complete_adoption_candidate_chirho(
        |held_storage_chirho, context_chirho, prepared_chirho| {
            commit_adoption_for_obligation_chirho(
                held_storage_chirho,
                context_chirho,
                &prepared_chirho,
            );
            let before_chirho = without_obligation_receipts_chirho(held_storage_chirho);
            let selector_chirho = selector_for_context_chirho(context_chirho);
            let obligation_chirho = in_doubt_obligation_chirho();
            let closed_evidence_chirho = ClosedEffectEvidenceChirho;
            let closed_intent_chirho = ClosedIntentVerifierChirho;
            let closed_terminal_chirho = ClosedTerminalVerifierChirho;
            let ports_chirho = obligation_actor_ports_chirho(
                held_storage_chirho,
                context_chirho,
                &closed_evidence_chirho,
                &closed_intent_chirho,
                &closed_terminal_chirho,
            );
            let minted_chirho =
                mint_actor_owned_gd7_losing_effect_obligation_with_hooks_for_test_chirho(
                    &context_chirho.plan_checkpoint_chirho.identity_chirho,
                    &selector_chirho,
                    &ports_chirho,
                    |plan_checkpoint_ref_chirho, plan_checkpoint_chirho, actual_selector_chirho| {
                        assert_eq!(
                            plan_checkpoint_ref_chirho,
                            context_chirho.plan_checkpoint_ref_chirho
                        );
                        assert_eq!(
                            plan_checkpoint_chirho,
                            context_chirho.plan_checkpoint_chirho
                        );
                        assert_eq!(actual_selector_chirho, &selector_chirho);
                        Ok(verified_obligation_chirho(
                            &selector_chirho,
                            obligation_chirho.clone(),
                        ))
                    },
                    |_minted_chirho| {},
                )
                .expect("the actor-owned exact adoption mints one obligation");
            assert_eq!(minted_chirho.obligation_chirho(), &obligation_chirho);
            assert_eq!(
                without_obligation_receipts_chirho(held_storage_chirho),
                before_chirho,
                "mint must not move the adoption head, candidate journal, projection, evidence, or ledger"
            );
            assert_eq!(obligation_receipt_count_chirho(held_storage_chirho), 1);

            let retry_refusal_chirho = expect_actor_mint_refusal_chirho(
                mint_actor_owned_gd7_losing_effect_obligation_with_hooks_for_test_chirho(
                    &context_chirho.plan_checkpoint_chirho.identity_chirho,
                    &selector_chirho,
                    &ports_chirho,
                    |_plan_checkpoint_ref_chirho,
                     _plan_checkpoint_chirho,
                     _actual_selector_chirho| {
                        Ok(verified_obligation_chirho(
                            &selector_chirho,
                            obligation_chirho.clone(),
                        ))
                    },
                    |_minted_chirho| {},
                ),
                "the same actor-owned obligation cannot mint twice",
            );
            assert!(matches!(
                retry_refusal_chirho,
                ResidentGd7HeldObligationMintRefusalChirho::MintChirho(
                    Gd7LosingEffectObligationMintRefusalChirho::MintedAwaitingConsumptionChirho {
                        ref receipt_ref_chirho,
                    }
                ) if receipt_ref_chirho == minted_chirho.receipt_ref_chirho()
            ));
            let rendered_chirho = retry_refusal_chirho.to_string();
            assert!(rendered_chirho.contains("awaiting verified item-5b consumption"));
            assert!(!rendered_chirho.contains("changed after durable"));
            assert!(!rendered_chirho.contains("collided"));
            assert_eq!(obligation_receipt_count_chirho(held_storage_chirho), 1);
            assert_eq!(
                without_obligation_receipts_chirho(held_storage_chirho),
                before_chirho
            );
        },
    );
}

#[test]
fn adoption_change_after_plan_verification_refuses_before_receipt_chirho() {
    with_complete_adoption_candidate_chirho(
        |held_storage_chirho, context_chirho, prepared_chirho| {
            commit_adoption_for_obligation_chirho(
                held_storage_chirho,
                context_chirho,
                &prepared_chirho,
            );
            let selector_chirho = selector_for_context_chirho(context_chirho);
            let obligation_chirho = in_doubt_obligation_chirho();
            let closed_evidence_chirho = ClosedEffectEvidenceChirho;
            let closed_intent_chirho = ClosedIntentVerifierChirho;
            let closed_terminal_chirho = ClosedTerminalVerifierChirho;
            let ports_chirho = obligation_actor_ports_chirho(
                held_storage_chirho,
                context_chirho,
                &closed_evidence_chirho,
                &closed_intent_chirho,
                &closed_terminal_chirho,
            );
            let refusal_chirho = expect_actor_mint_refusal_chirho(
                mint_actor_owned_gd7_losing_effect_obligation_with_hooks_for_test_chirho(
                    &context_chirho.plan_checkpoint_chirho.identity_chirho,
                    &selector_chirho,
                    &ports_chirho,
                    |_plan_checkpoint_ref_chirho,
                     _plan_checkpoint_chirho,
                     _actual_selector_chirho| {
                        let changed_ref_chirho = publish_reconciliation_checkpoint_as_active_chirho(
                            held_storage_chirho,
                            context_chirho.plan_checkpoint_chirho.clone(),
                            context_chirho.held_signer_chirho,
                        );
                        assert_eq!(
                            changed_ref_chirho,
                            context_chirho.plan_checkpoint_ref_chirho
                        );
                        Ok(verified_obligation_chirho(
                            &selector_chirho,
                            obligation_chirho.clone(),
                        ))
                    },
                    |_minted_chirho| {},
                ),
                "a PlanSealed rollback after plan verification must refuse before mint",
            );
            assert_eq!(
                refusal_chirho,
                ResidentGd7HeldObligationMintRefusalChirho::AdoptionChangedBeforeMintChirho
            );
            let rendered_chirho = refusal_chirho.to_string();
            assert!(rendered_chirho.contains("changed before durable"));
            assert!(!rendered_chirho.contains("changed after durable"));
            assert!(!rendered_chirho.contains("awaiting verified"));
            assert_eq!(obligation_receipt_count_chirho(held_storage_chirho), 0);
        },
    );
}

#[test]
fn adoption_change_after_durable_receipt_returns_no_token_and_names_resume_chirho() {
    with_complete_adoption_candidate_chirho(
        |held_storage_chirho, context_chirho, prepared_chirho| {
            commit_adoption_for_obligation_chirho(
                held_storage_chirho,
                context_chirho,
                &prepared_chirho,
            );
            let selector_chirho = selector_for_context_chirho(context_chirho);
            let obligation_chirho = in_doubt_obligation_chirho();
            let closed_evidence_chirho = ClosedEffectEvidenceChirho;
            let closed_intent_chirho = ClosedIntentVerifierChirho;
            let closed_terminal_chirho = ClosedTerminalVerifierChirho;
            let ports_chirho = obligation_actor_ports_chirho(
                held_storage_chirho,
                context_chirho,
                &closed_evidence_chirho,
                &closed_intent_chirho,
                &closed_terminal_chirho,
            );
            let refusal_chirho = expect_actor_mint_refusal_chirho(
                mint_actor_owned_gd7_losing_effect_obligation_with_hooks_for_test_chirho(
                    &context_chirho.plan_checkpoint_chirho.identity_chirho,
                    &selector_chirho,
                    &ports_chirho,
                    |_plan_checkpoint_ref_chirho,
                     _plan_checkpoint_chirho,
                     _actual_selector_chirho| {
                        Ok(verified_obligation_chirho(
                            &selector_chirho,
                            obligation_chirho.clone(),
                        ))
                    },
                    |minted_chirho| {
                        assert_eq!(obligation_receipt_count_chirho(held_storage_chirho), 1);
                        let changed_ref_chirho = publish_reconciliation_checkpoint_as_active_chirho(
                            held_storage_chirho,
                            context_chirho.plan_checkpoint_chirho.clone(),
                            context_chirho.held_signer_chirho,
                        );
                        assert_eq!(
                            changed_ref_chirho,
                            context_chirho.plan_checkpoint_ref_chirho
                        );
                        assert!(!minted_chirho.receipt_ref_chirho().is_empty());
                    },
                ),
                "a changed selector after durable receipt must not release the runtime token",
            );
            let ResidentGd7HeldObligationMintRefusalChirho::AdoptionChangedAfterMintChirho {
                receipt_ref_chirho,
            } = &refusal_chirho
            else {
                panic!("expected the exact post-receipt adoption-change refusal");
            };
            assert_eq!(receipt_ref_chirho.len(), 64);
            let rendered_chirho = refusal_chirho.to_string();
            assert!(rendered_chirho.contains(receipt_ref_chirho));
            assert!(rendered_chirho.contains("awaiting verified item-5b resume"));
            assert!(!rendered_chirho.contains("changed before durable"));
            assert!(!rendered_chirho.contains("collided"));
            assert_eq!(obligation_receipt_count_chirho(held_storage_chirho), 1);
        },
    );
}

fn commit_adoption_for_obligation_chirho(
    held_storage_chirho: &SimStorageChirho,
    context_chirho: &ForkBaselineTestContextChirho<'_>,
    prepared_chirho: &ResidentGd7HeldPreparedAdoptionChirho,
) {
    assert!(matches!(
        commit_or_reload_gd7_held_adoption_for_test_chirho(
            &context_chirho.plan_checkpoint_chirho.identity_chirho,
            &context_chirho
                .plan_checkpoint_chirho
                .winner_fork_witness_object_digest_chirho,
            prepared_chirho,
            &adoption_commit_ports_chirho(held_storage_chirho, context_chirho),
        )
        .expect("commit the exact adoption selector before obligation mint"),
        ResidentGd7HeldAdoptionCommitOutcomeChirho::CommittedChirho(_)
    ));
}

fn selector_for_context_chirho(
    context_chirho: &ForkBaselineTestContextChirho<'_>,
) -> Gd7LosingEffectObligationSelectorChirho {
    Gd7LosingEffectObligationSelectorChirho::new_chirho(
        context_chirho
            .plan_checkpoint_chirho
            .state_chirho
            .sealed_plan_ref_chirho
            .as_ref()
            .expect("fixture checkpoint names a sealed plan"),
        0,
    )
    .expect("fixture selector is a canonical plan coordinate")
}

fn verified_obligation_chirho(
    selector_chirho: &Gd7LosingEffectObligationSelectorChirho,
    obligation_chirho: Gd7EffectPlanObligationChirho,
) -> crate::reconciliation_chirho::VerifiedGd7SealedPlanObligationChirho {
    verified_gd7_sealed_plan_obligation_for_test_chirho(
        selector_chirho.plan_page_ref_chirho().to_owned(),
        0,
        selector_chirho.obligation_index_chirho(),
        obligation_chirho,
    )
}

fn in_doubt_obligation_chirho() -> Gd7EffectPlanObligationChirho {
    Gd7EffectPlanObligationChirho {
        kind_chirho: Gd7EffectPlanObligationKindChirho::InDoubtHoldOnLosingForkChirho,
        lineage_chirho: Gd7EffectLineageChirho::ForwardChirho,
        intent_ref_chirho: DigestChirho("1".repeat(64)),
        original_effect_key_chirho: None,
        reversion_contract_digest_chirho: DigestChirho("2".repeat(64)),
        control_chirho: EscrowControlChirho {
            saga_id_chirho: DigestChirho("3".repeat(64)),
            step_chirho: 1,
        },
        outcome_ref_chirho: None,
        source_seq_chirho: 6,
        source_record_digest_chirho: "4".repeat(64),
        terminal_marker_object_digest_chirho: None,
    }
}

fn obligation_actor_ports_chirho<'borrow_chirho, 'fixture_chirho: 'borrow_chirho>(
    held_storage_chirho: &'borrow_chirho SimStorageChirho,
    context_chirho: &'borrow_chirho ForkBaselineTestContextChirho<'fixture_chirho>,
    evidence_chirho: &'borrow_chirho ClosedEffectEvidenceChirho,
    intent_chirho: &'borrow_chirho ClosedIntentVerifierChirho,
    terminal_chirho: &'borrow_chirho ClosedTerminalVerifierChirho,
) -> ResidentGd7HeldObligationMintActorPortsChirho<'borrow_chirho> {
    ResidentGd7HeldObligationMintActorPortsChirho {
        authority_storage_chirho: held_storage_chirho,
        candidate_storage_chirho: held_storage_chirho,
        held_verifier_chirho: context_chirho.held_signer_chirho,
        held_signer_chirho: Some(context_chirho.held_signer_chirho),
        winner_control_verifier_chirho: context_chirho.winner_signer_chirho,
        winner_ledger_verifier_chirho: context_chirho.winner_journal_signer_chirho,
        effect_proof_ports_chirho: Gd7EffectProofPortsChirho::new_chirho(
            evidence_chirho,
            intent_chirho,
            terminal_chirho,
        ),
        clock_chirho: context_chirho.journal_ports_chirho.clock_chirho,
        membership_chirho: context_chirho.journal_ports_chirho.membership_chirho,
        kind_registry_chirho: context_chirho.journal_ports_chirho.kind_registry_chirho,
        authority_chirho: context_chirho.journal_ports_chirho.authority_chirho,
        cluster_id_chirho: context_chirho.cluster_chirho,
        group_digest_chirho: &context_chirho
            .plan_checkpoint_chirho
            .identity_chirho
            .consistency_group_digest_chirho,
    }
}

fn obligation_receipt_count_chirho(storage_chirho: &SimStorageChirho) -> usize {
    storage_chirho
        .snapshot_chirho()
        .keys()
        .filter(|path_chirho| {
            path_chirho
                .starts_with("gd7-reconciliation-chirho/losing-effect-obligation-mints-chirho/")
        })
        .count()
}

fn without_obligation_receipts_chirho(
    storage_chirho: &SimStorageChirho,
) -> std::collections::BTreeMap<String, Vec<u8>> {
    storage_chirho
        .snapshot_chirho()
        .into_iter()
        .filter(|(path_chirho, _bytes_chirho)| {
            !path_chirho
                .starts_with("gd7-reconciliation-chirho/losing-effect-obligation-mints-chirho/")
        })
        .collect()
}

fn expect_actor_mint_refusal_chirho(
    result_chirho: std::result::Result<
        crate::reconciliation_chirho::MintedGd7LosingEffectObligationChirho,
        ResidentGd7HeldObligationMintRefusalChirho,
    >,
    message_chirho: &str,
) -> ResidentGd7HeldObligationMintRefusalChirho {
    match result_chirho {
        Ok(_minted_chirho) => panic!("{message_chirho}"),
        Err(refusal_chirho) => refusal_chirho,
    }
}
