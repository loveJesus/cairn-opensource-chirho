// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_effect_commit_chirho::compensation_chirho::{
    authorize_effect_compensation_chirho, CompensationAuthorizationFactsChirho,
    CompensationAuthorizationViewChirho, CompensationAuthorizationViewErrorChirho,
    CompensationBreakerVerdictChirho, EffectCompensationAuthorizationOutcomeChirho,
};
use cairn_effect_commit_chirho::intent_chirho::{
    canonical_effect_intent_line_chirho, sign_effect_intent_chirho, EffectIntentChirho,
    VerifiedEffectIntentChirho, EFFECT_INTENT_KEY_PREFIX_CHIRHO, EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};

struct PermittingCompensationViewChirho;

impl CompensationAuthorizationViewChirho for PermittingCompensationViewChirho {
    fn derive_chirho(
        &self,
        candidate_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<CompensationAuthorizationFactsChirho, CompensationAuthorizationViewErrorChirho>
    {
        let original_effect_key_chirho = candidate_chirho
            .intent_chirho()
            .original_effect_key_chirho
            .clone()
            .expect("the test compensation intent carries its original effect key");
        Ok(CompensationAuthorizationFactsChirho::new_chirho(
            original_effect_key_chirho.clone(),
            original_effect_key_chirho,
            1,
            4,
            CompensationBreakerVerdictChirho::PermittedChirho,
        ))
    }
}

fn assert_handoff_refusal_chirho<T: std::fmt::Debug>(
    result_chirho: Result<T, ResidentLedgerAuthorityRefusalChirho>,
) {
    assert_eq!(
        result_chirho.unwrap_err(),
        ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho {
            reason_chirho: LocalAppendAuthorityRefusalChirho::HandoffActiveChirho,
        }
    );
}

/// RETARGETED, 2026-08-05, for the GD7 resume step ruled (a) by L.J. — and only the NAME moved.
///
/// The compensation door is now the one lawful narrowing of the append freeze, so under an active
/// marker it no longer stops at the ordinary acquisition: it asks this node's own durable, signed
/// handoff head whether an ACCEPTED attempt exists. This fixture arms the elector marker directly
/// and writes no durable head, so the lane declines at its FIRST evidence gate and reports which one.
///
/// WHAT DID NOT CHANGE, and it is the part this test exists for: the append is still refused, and
/// the caller's `assert_unchanged_chirho()` still proves the journal cut and every byte under the
/// root are untouched. The freeze holds; only the refusal became more specific.
///
/// WHAT EACH FUTURE OUTCOME MEANS, so the next reader is not left with archaeology:
/// * `LocalGenerationRefusedChirho { HandoffActiveChirho }` here means the compensation lane stopped
///   reaching the seam — the resume step regressed to pre-(a) behaviour.
/// * A lane refusal naming a DIFFERENT gate ("not accepted" rather than the missing head) means this
///   fixture started producing a durable head; read the new detail before touching this assertion.
/// * An `Ok` means an append was ADMITTED with no durable accepted evidence at all. That is the one
///   outcome that is a real defect, and it must never be papered over.
fn assert_compensation_lane_declined_without_durable_evidence_chirho<T: std::fmt::Debug>(
    result_chirho: Result<T, ResidentLedgerAuthorityRefusalChirho>,
) {
    assert_eq!(
        result_chirho.unwrap_err(),
        ResidentLedgerAuthorityRefusalChirho::Gd7CompensationLaneRefusedChirho {
            detail_chirho: "this node owns no durable GD7 winner handoff head".to_owned(),
        }
    );
}

#[test]
fn active_handoff_freezes_every_resident_append_door_without_moving_the_cut_chirho() {
    with_bound_resident_fixture_chirho(
        "resident-authority-handoff-fence",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let local_authority_chirho = elector_chirho.local_append_authority_handle_chirho();
            let mut resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    local_authority_chirho.clone(),
                )
                .unwrap();
            let signers_chirho = HostLedgerSignersChirho::load_existing_chirho(
                root_chirho,
                &crate::tests_chirho::signer_refs_chirho(),
            )
            .unwrap();
            let digest_chirho =
                |character_chirho: char| DigestChirho(character_chirho.to_string().repeat(64));
            let original_effect_key_chirho =
                format!("{EFFECT_INTENT_KEY_PREFIX_CHIRHO}{}", "a".repeat(64));
            let compensation_intent_chirho = sign_effect_intent_chirho(
                EffectIntentChirho {
                    schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
                    journal_cut_chirho: resident_chirho.effect_intent_cut_chirho(None).unwrap(),
                    contract_set_digest_chirho: digest_chirho('b'),
                    door_chirho: serde_json::from_value(serde_json::json!({
                        "effect_node_chirho": "c".repeat(64),
                        "capability_fingerprint_chirho": "d".repeat(64),
                    }))
                    .unwrap(),
                    reversion_contract_digest_chirho: digest_chirho('e'),
                    request_ref_chirho: digest_chirho('f'),
                    request_context_ref_chirho: digest_chirho('1'),
                    evidence_refs_chirho: vec![digest_chirho('2')],
                    resolved_price_chirho: AssetOpChirho {
                        amount_chirho: 1,
                        kind_id_chirho: AssetKindIdChirho("credits-chirho".to_owned()),
                        kind_policy_ref_chirho: AssetKindRefChirho(digest_chirho('3')),
                        rounding_chirho: RoundingChirho::ExactChirho,
                    },
                    payer_account_chirho: resident_account_chirho(),
                    effect_step_chirho: 1,
                    attribution_chirho: AttributionChirho::PlatformChirho,
                    original_effect_key_chirho: Some(original_effect_key_chirho),
                    sig_chirho: String::new(),
                    key_id_chirho: String::new(),
                },
                &signers_chirho.effect_intent_chirho,
            )
            .unwrap();
            let compensation_line_chirho =
                canonical_effect_intent_line_chirho(&compensation_intent_chirho).unwrap();
            let compensation_authorization_chirho = match authorize_effect_compensation_chirho(
                &compensation_line_chirho,
                &signers_chirho.effect_intent_chirho,
                &PermittingCompensationViewChirho,
            )
            .unwrap()
            {
                EffectCompensationAuthorizationOutcomeChirho::AuthorizedChirho(
                    authorization_chirho,
                ) => authorization_chirho,
                EffectCompensationAuthorizationOutcomeChirho::PendingManualChirho(_) => {
                    panic!("the permitting view must authorize the test compensation")
                }
            };

            let accepted_before_handoff_chirho = resident_chirho
                .append_preactivation_chirho(
                    &ResidentLedgerAppendPermitChirho::for_test_chirho(),
                    resident_mint_request_chirho(1, "accepted-before-handoff-chirho"),
                )
                .expect("an append immediately before handoff preparation commits");
            let preparation_chirho = local_authority_chirho
                .try_prepare_handoff_chirho(&"9".repeat(64))
                .unwrap();
            let observe_cut_chirho = || {
                LedgerJournalChirho::open_read_only_chirho(
                    JournalPortsChirho {
                        storage_chirho: ports_chirho.storage_chirho,
                        signer_chirho: ports_chirho.signer_chirho,
                        clock_chirho: ports_chirho.clock_chirho,
                        membership_chirho: ports_chirho.membership_chirho,
                        kind_registry_chirho: ports_chirho.kind_registry_chirho,
                        authority_chirho: ports_chirho.authority_chirho,
                    },
                    journal_path_chirho.clone(),
                    cluster_id_chirho,
                )
                .unwrap()
                .effect_intent_cut_chirho()
            };
            let frozen_cut_chirho = observe_cut_chirho();
            assert_eq!(
                frozen_cut_chirho.tail_seq_chirho,
                accepted_before_handoff_chirho.append_chirho.seq_chirho,
                "the accepted pre-handoff append must be inside the frozen cut"
            );
            let active_handoff_guard_chirho = preparation_chirho.activate_chirho();
            let frozen_bytes_chirho = snapshot_files_chirho(root_chirho);
            let assert_unchanged_chirho = || {
                assert_eq!(observe_cut_chirho(), frozen_cut_chirho);
                assert_eq!(snapshot_files_chirho(root_chirho), frozen_bytes_chirho);
            };
            assert_eq!(
                resident_chirho
                    .probe_during_handoff_chirho(&active_handoff_guard_chirho)
                    .expect("the exact handoff guard leaves read-only resident probes available")
                    .journal_tail_seq_chirho,
                frozen_cut_chirho.tail_seq_chirho
            );
            drop(active_handoff_guard_chirho);

            assert_handoff_refusal_chirho(resident_chirho.append_preactivation_chirho(
                &ResidentLedgerAppendPermitChirho::for_test_chirho(),
                resident_mint_request_chirho(1, "handoff-preactivation-chirho"),
            ));
            assert_unchanged_chirho();
            assert_handoff_refusal_chirho(resident_chirho.record_effect_hold_chirho(
                &compensation_line_chirho,
                &signers_chirho.effect_intent_chirho,
            ));
            assert_unchanged_chirho();
            // The one door ruled (a) narrowed. It still refuses and still moves nothing; see the
            // retargeted assertion's own header for why the NAME differs and what each future
            // outcome would mean.
            assert_compensation_lane_declined_without_durable_evidence_chirho(
                resident_chirho.record_effect_compensation_hold_chirho(
                    &compensation_line_chirho,
                    &signers_chirho.effect_intent_chirho,
                    &compensation_authorization_chirho,
                ),
            );
            assert_unchanged_chirho();
            assert_handoff_refusal_chirho(resident_chirho.record_effect_terminal_chirho(
                &compensation_line_chirho,
                &signers_chirho.effect_intent_chirho,
                "",
                &signers_chirho.effect_terminal_chirho,
            ));
            assert_unchanged_chirho();
            assert_handoff_refusal_chirho(resident_chirho.record_testkind_loss_witness_chirho(
                resident_mint_request_chirho(1, "handoff-loss-witness-chirho"),
            ));
            assert_unchanged_chirho();
        },
    );
}
