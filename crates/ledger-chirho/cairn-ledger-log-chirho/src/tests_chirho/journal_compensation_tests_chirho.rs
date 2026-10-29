// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! CF3 compensation journal-door proofs: dedicated namespace, one coordinate per original K,
//! append/replay conflict refusal, terminal consumption, and active-Hold receipt retention.

use crate::checkpoint_chirho::parse_head_checkpoint_chirho;
use crate::journal_chirho::{JournalErrorChirho, LedgerJournalChirho};
use crate::journal_effect_chirho::EffectCompensationJournalErrorChirho;
use crate::journal_effect_tests_chirho::{
    digest_chirho, funded_engine_chirho, signed_intent_chirho, signed_terminal_line_chirho,
    FakeEffectRootChirho, DIGEST_A_CHIRHO, DIGEST_B_CHIRHO, DIGEST_C_CHIRHO, DIGEST_D_CHIRHO,
    DIGEST_E_CHIRHO, DIGEST_F_CHIRHO,
};
use crate::journal_tests_chirho::{
    transfer_request_chirho, HarnessChirho, MONEY_KIND_CHIRHO, MONEY_POLICY_REF_CHIRHO,
};
use crate::ports_chirho::{LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho};
use cairn_effect_commit_chirho::compensation_chirho::*;
use cairn_effect_commit_chirho::intent_chirho::*;
use cairn_effect_commit_chirho::terminal_chirho::EffectTerminalDispositionChirho;
use cairn_ledger_model_chirho::record_chirho::LegDeltaChirho;
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_record_line_chirho, ledger_record_signed_content_line_chirho,
    parse_canonical_ledger_journal_line_chirho, stored_line_digest_chirho, LedgerJournalLineChirho,
};
use cairn_ledger_model_chirho::LogIdChirho;

struct PermittingCompensationViewChirho {
    original_effect_key_chirho: String,
}

impl CompensationAuthorizationViewChirho for PermittingCompensationViewChirho {
    fn derive_chirho(
        &self,
        candidate_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<CompensationAuthorizationFactsChirho, CompensationAuthorizationViewErrorChirho>
    {
        if candidate_chirho
            .intent_chirho()
            .original_effect_key_chirho
            .as_deref()
            != Some(self.original_effect_key_chirho.as_str())
        {
            return Err(CompensationAuthorizationViewErrorChirho::RefusedChirho {
                detail_chirho: "candidate names a different original effect K".to_owned(),
            });
        }
        Ok(CompensationAuthorizationFactsChirho::new_chirho(
            self.original_effect_key_chirho.clone(),
            self.original_effect_key_chirho.clone(),
            1,
            3,
            CompensationBreakerVerdictChirho::PermittedChirho,
        ))
    }
}

fn original_effect_key_chirho() -> String {
    format!("{EFFECT_INTENT_KEY_PREFIX_CHIRHO}{DIGEST_F_CHIRHO}")
}

fn signed_compensation_intent_chirho(
    engine_chirho: &LedgerJournalChirho<'_>,
    root_chirho: &FakeEffectRootChirho,
    original_effect_key_chirho: &str,
    request_ref_chirho: &str,
) -> (EffectIntentChirho, String) {
    let (mut intent_chirho, _) =
        signed_intent_chirho(engine_chirho, root_chirho, MONEY_POLICY_REF_CHIRHO);
    intent_chirho.original_effect_key_chirho = Some(original_effect_key_chirho.to_owned());
    intent_chirho.request_ref_chirho = digest_chirho(request_ref_chirho);
    intent_chirho.sig_chirho.clear();
    intent_chirho.key_id_chirho.clear();
    let intent_chirho = sign_effect_intent_chirho(intent_chirho, root_chirho).unwrap();
    let line_chirho = canonical_effect_intent_line_chirho(&intent_chirho).unwrap();
    (intent_chirho, line_chirho)
}

fn authorize_compensation_chirho(
    line_chirho: &str,
    root_chirho: &FakeEffectRootChirho,
    original_effect_key_chirho: &str,
) -> VerifiedEffectCompensationChirho {
    let view_chirho = PermittingCompensationViewChirho {
        original_effect_key_chirho: original_effect_key_chirho.to_owned(),
    };
    match authorize_effect_compensation_chirho(line_chirho, root_chirho, &view_chirho).unwrap() {
        EffectCompensationAuthorizationOutcomeChirho::AuthorizedChirho(token_chirho) => {
            token_chirho
        }
        EffectCompensationAuthorizationOutcomeChirho::PendingManualChirho(_) => {
            panic!("permitting compensation view must authorize")
        }
    }
}

#[test]
fn compensation_namespace_requires_its_authorized_door_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = funded_engine_chirho(&harness_chirho);
    let root_chirho = FakeEffectRootChirho {
        root_chirho: "compensation-root-chirho",
    };
    let original_key_chirho = original_effect_key_chirho();
    let (_intent_chirho, line_chirho) = signed_compensation_intent_chirho(
        &engine_chirho,
        &root_chirho,
        &original_key_chirho,
        DIGEST_A_CHIRHO,
    );
    let token_chirho =
        authorize_compensation_chirho(&line_chirho, &root_chirho, &original_key_chirho);
    let tail_before_chirho = engine_chirho.tail_seq_chirho();

    assert!(matches!(
        engine_chirho.append_effect_intent_chirho(&line_chirho, &root_chirho),
        Err(JournalErrorChirho::EffectIntentChirho { .. })
    ));
    let mut generic_request_chirho = transfer_request_chirho(
        "issuer-chirho",
        "alice-chirho",
        1,
        "placeholder-compensation-key-chirho",
    );
    generic_request_chirho.idempotency_key_chirho =
        format!("{EFFECT_COMPENSATION_KEY_PREFIX_CHIRHO}XYZ");
    assert!(matches!(
        engine_chirho.append_chirho(generic_request_chirho),
        Err(JournalErrorChirho::EffectIntentChirho { .. })
    ));
    assert_eq!(engine_chirho.tail_seq_chirho(), tail_before_chirho);

    engine_chirho
        .append_effect_compensation_chirho(&line_chirho, &root_chirho, &token_chirho)
        .unwrap();
}

#[test]
fn one_compensation_coordinate_returns_same_receipt_and_refuses_different_intent_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = funded_engine_chirho(&harness_chirho);
    let root_chirho = FakeEffectRootChirho {
        root_chirho: "compensation-root-chirho",
    };
    let original_key_chirho = original_effect_key_chirho();
    let (_first_intent_chirho, first_line_chirho) = signed_compensation_intent_chirho(
        &engine_chirho,
        &root_chirho,
        &original_key_chirho,
        DIGEST_A_CHIRHO,
    );
    let first_token_chirho =
        authorize_compensation_chirho(&first_line_chirho, &root_chirho, &original_key_chirho);
    let first_receipt_chirho = engine_chirho
        .append_effect_compensation_chirho(&first_line_chirho, &root_chirho, &first_token_chirho)
        .unwrap();
    assert_eq!(
        engine_chirho
            .append_effect_compensation_chirho(
                &first_line_chirho,
                &root_chirho,
                &first_token_chirho,
            )
            .unwrap(),
        first_receipt_chirho
    );

    let (_different_intent_chirho, different_line_chirho) = signed_compensation_intent_chirho(
        &engine_chirho,
        &root_chirho,
        &original_key_chirho,
        DIGEST_B_CHIRHO,
    );
    let different_token_chirho =
        authorize_compensation_chirho(&different_line_chirho, &root_chirho, &original_key_chirho);
    let tail_before_conflict_chirho = engine_chirho.tail_seq_chirho();
    assert!(matches!(
        engine_chirho.append_effect_compensation_chirho(
            &different_line_chirho,
            &root_chirho,
            &different_token_chirho,
        ),
        Err(EffectCompensationJournalErrorChirho::IntentConflictChirho { .. })
    ));
    assert_eq!(engine_chirho.tail_seq_chirho(), tail_before_conflict_chirho);
}

#[test]
fn compensation_terminal_consumes_hold_and_fast_open_restores_receipt_chirho() {
    let mut harness_chirho = HarnessChirho::new_chirho();
    harness_chirho.registry_chirho.settlement_owner_chirho = Some("bob-chirho".to_owned());
    let mut engine_chirho = funded_engine_chirho(&harness_chirho);
    let intent_root_chirho = FakeEffectRootChirho {
        root_chirho: "compensation-root-chirho",
    };
    let terminal_root_chirho = FakeEffectRootChirho {
        root_chirho: "terminal-root-chirho",
    };
    let original_key_chirho = original_effect_key_chirho();
    let (intent_chirho, line_chirho) = signed_compensation_intent_chirho(
        &engine_chirho,
        &intent_root_chirho,
        &original_key_chirho,
        DIGEST_A_CHIRHO,
    );
    let token_chirho =
        authorize_compensation_chirho(&line_chirho, &intent_root_chirho, &original_key_chirho);
    engine_chirho
        .append_effect_compensation_chirho(&line_chirho, &intent_root_chirho, &token_chirho)
        .unwrap();
    let terminal_line_chirho = signed_terminal_line_chirho(
        &intent_chirho,
        &terminal_root_chirho,
        EffectTerminalDispositionChirho::CommittedChirho {
            result_ref_chirho: digest_chirho(DIGEST_D_CHIRHO),
        },
        DIGEST_C_CHIRHO,
    );
    let terminal_receipt_chirho = engine_chirho
        .append_effect_terminal_chirho(
            &line_chirho,
            &intent_root_chirho,
            &terminal_line_chirho,
            &terminal_root_chirho,
        )
        .unwrap();
    assert_eq!(
        engine_chirho
            .head_state_chirho(&LogIdChirho::new_chirho("alice-chirho", MONEY_KIND_CHIRHO))
            .unwrap()
            .held_chirho,
        0
    );
    assert_eq!(
        engine_chirho
            .head_state_chirho(&LogIdChirho::new_chirho("bob-chirho", MONEY_KIND_CHIRHO))
            .unwrap()
            .credits_total_chirho,
        10
    );
    assert!(engine_chirho.active_effect_intent_refs_chirho().is_empty());
    let inventory_chirho = engine_chirho.verified_effect_receipt_inventory_chirho();
    assert_eq!(inventory_chirho.len(), 1);
    assert_eq!(
        inventory_chirho[0].intent_ref_chirho,
        effect_intent_ref_chirho(&intent_chirho).unwrap()
    );
    assert_eq!(
        inventory_chirho[0].control_saga_id_chirho,
        Some(
            parse_effect_compensation_key_chirho(
                &effect_compensation_key_chirho(&original_key_chirho).unwrap(),
            )
            .unwrap()
        )
    );
    assert!(inventory_chirho[0].terminal_outcome_ref_chirho.is_some());
    assert_eq!(
        inventory_chirho[0]
            .terminal_receipt_chirho
            .as_ref()
            .unwrap()
            .seq_chirho,
        terminal_receipt_chirho.seq_chirho
    );

    engine_chirho.write_head_checkpoint_chirho().unwrap();
    let sidecar_path_chirho = StoragePathChirho(format!(
        "{}.head-checkpoint-chirho",
        harness_chirho.path_chirho().0
    ));
    let checkpoint_bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&sidecar_path_chirho)
        .unwrap()
        .unwrap();
    assert!(String::from_utf8(checkpoint_bytes_chirho.clone())
        .unwrap()
        .contains("control_saga_id_chirho"));
    let checkpoint_chirho = parse_head_checkpoint_chirho(&checkpoint_bytes_chirho).unwrap();
    let compensation_key_chirho = effect_compensation_key_chirho(&original_key_chirho).unwrap();
    assert!(checkpoint_chirho
        .effect_receipt_window_chirho
        .get(&compensation_key_chirho)
        .unwrap()
        .control_saga_id_chirho
        .is_some());
    drop(engine_chirho);

    let mut reopened_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .unwrap();
    assert!(reopened_chirho.last_open_was_fast_chirho());
    assert_eq!(
        reopened_chirho
            .append_effect_terminal_chirho(
                &line_chirho,
                &intent_root_chirho,
                &terminal_line_chirho,
                &terminal_root_chirho,
            )
            .unwrap(),
        terminal_receipt_chirho
    );
}

#[test]
fn active_compensation_hold_retains_receipt_across_age_and_fast_open_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = funded_engine_chirho(&harness_chirho);
    let root_chirho = FakeEffectRootChirho {
        root_chirho: "compensation-root-chirho",
    };
    let original_key_chirho = original_effect_key_chirho();
    let (intent_chirho, line_chirho) = signed_compensation_intent_chirho(
        &engine_chirho,
        &root_chirho,
        &original_key_chirho,
        DIGEST_A_CHIRHO,
    );
    let token_chirho =
        authorize_compensation_chirho(&line_chirho, &root_chirho, &original_key_chirho);
    let receipt_chirho = engine_chirho
        .append_effect_compensation_chirho(&line_chirho, &root_chirho, &token_chirho)
        .unwrap();
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    drop(engine_chirho);

    let mut reopened_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .unwrap();
    assert!(reopened_chirho.last_open_was_fast_chirho());
    harness_chirho.clock_chirho.now_ms_chirho.set(3_000);
    reopened_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            1,
            "advance-compensation-age-chirho",
        ))
        .unwrap();
    let tail_before_retry_chirho = reopened_chirho.tail_seq_chirho();
    assert_eq!(
        reopened_chirho
            .append_effect_compensation_chirho(&line_chirho, &root_chirho, &token_chirho)
            .unwrap(),
        receipt_chirho
    );
    assert_eq!(reopened_chirho.tail_seq_chirho(), tail_before_retry_chirho);
    assert_eq!(
        reopened_chirho.active_effect_intent_refs_chirho(),
        vec![effect_intent_ref_chirho(&intent_chirho).unwrap()]
    );
}

#[test]
fn chain_valid_duplicate_compensation_key_fails_load_before_fold_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = funded_engine_chirho(&harness_chirho);
    let root_chirho = FakeEffectRootChirho {
        root_chirho: "compensation-root-chirho",
    };
    let original_key_chirho = original_effect_key_chirho();
    let (_intent_chirho, line_chirho) = signed_compensation_intent_chirho(
        &engine_chirho,
        &root_chirho,
        &original_key_chirho,
        DIGEST_A_CHIRHO,
    );
    let token_chirho =
        authorize_compensation_chirho(&line_chirho, &root_chirho, &original_key_chirho);
    engine_chirho
        .append_effect_compensation_chirho(&line_chirho, &root_chirho, &token_chirho)
        .unwrap();

    let journal_bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&harness_chirho.path_chirho())
        .unwrap()
        .unwrap();
    let journal_text_chirho = String::from_utf8(journal_bytes_chirho).unwrap();
    let last_line_chirho = journal_text_chirho.lines().last().unwrap();
    let mut forged_chirho =
        match parse_canonical_ledger_journal_line_chirho(last_line_chirho).unwrap() {
            LedgerJournalLineChirho::RecordChirho(record_chirho) => record_chirho,
            LedgerJournalLineChirho::GenesisChirho(_) => {
                panic!("compensation Hold tail must be a record")
            }
        };
    forged_chirho.seq_chirho += 1;
    forged_chirho.prev_chirho = stored_line_digest_chirho(last_line_chirho);
    forged_chirho.hlc_chirho.logical_chirho += 1;
    forged_chirho.provenance_chirho = Some(digest_chirho(DIGEST_E_CHIRHO));
    for leg_chirho in &mut forged_chirho.legs_chirho {
        leg_chirho.post_chirho.held_chirho += leg_chirho.amount_chirho;
    }
    forged_chirho.sig_chirho.clear();
    let signed_content_chirho = ledger_record_signed_content_line_chirho(&forged_chirho).unwrap();
    forged_chirho.sig_chirho = harness_chirho
        .signer_chirho
        .sign_chirho(&signed_content_chirho)
        .unwrap();
    let mut forged_bytes_chirho = canonical_ledger_record_line_chirho(&forged_chirho)
        .unwrap()
        .into_bytes();
    forged_bytes_chirho.push(b'\n');
    harness_chirho
        .storage_chirho
        .append_durable_chirho(&harness_chirho.path_chirho(), &forged_bytes_chirho)
        .unwrap();
    drop(engine_chirho);

    match LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    ) {
        Err(JournalErrorChirho::ChainChirho { detail_chirho }) => assert!(
            detail_chirho.contains("duplicate reserved CF3 intent key"),
            "duplicate compensation K must fail at the shared receipt transition: {detail_chirho}"
        ),
        Err(error_chirho) => panic!("unexpected replay refusal: {error_chirho:?}"),
        Ok(_) => panic!("duplicate compensation K must fail load closed"),
    }
}

#[test]
fn malformed_compensation_prefix_fails_load_before_fold_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let engine_chirho = funded_engine_chirho(&harness_chirho);
    let journal_bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&harness_chirho.path_chirho())
        .unwrap()
        .unwrap();
    let journal_text_chirho = String::from_utf8(journal_bytes_chirho).unwrap();
    let last_line_chirho = journal_text_chirho.lines().last().unwrap();
    let mut forged_chirho =
        match parse_canonical_ledger_journal_line_chirho(last_line_chirho).unwrap() {
            LedgerJournalLineChirho::RecordChirho(record_chirho) => record_chirho,
            LedgerJournalLineChirho::GenesisChirho(_) => {
                panic!("funding tail must be a transfer record")
            }
        };
    forged_chirho.seq_chirho += 1;
    forged_chirho.prev_chirho = stored_line_digest_chirho(last_line_chirho);
    forged_chirho.hlc_chirho.logical_chirho += 1;
    forged_chirho.idempotency_key_chirho = format!("{EFFECT_COMPENSATION_KEY_PREFIX_CHIRHO}XYZ");
    for leg_chirho in &mut forged_chirho.legs_chirho {
        match leg_chirho.delta_chirho {
            LegDeltaChirho::CreditChirho => {
                leg_chirho.post_chirho.credits_total_chirho += leg_chirho.amount_chirho;
            }
            LegDeltaChirho::DebitChirho => {
                leg_chirho.post_chirho.debits_total_chirho += leg_chirho.amount_chirho;
            }
            _ => panic!("funding transfer must carry only credit/debit legs"),
        }
    }
    forged_chirho.sig_chirho.clear();
    let signed_content_chirho = ledger_record_signed_content_line_chirho(&forged_chirho).unwrap();
    forged_chirho.sig_chirho = harness_chirho
        .signer_chirho
        .sign_chirho(&signed_content_chirho)
        .unwrap();
    let mut forged_bytes_chirho = canonical_ledger_record_line_chirho(&forged_chirho)
        .unwrap()
        .into_bytes();
    forged_bytes_chirho.push(b'\n');
    harness_chirho
        .storage_chirho
        .append_durable_chirho(&harness_chirho.path_chirho(), &forged_bytes_chirho)
        .unwrap();
    drop(engine_chirho);

    match LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    ) {
        Err(JournalErrorChirho::ChainChirho { detail_chirho }) => assert!(
            detail_chirho.contains("malformed reserved CF3 compensation key"),
            "malformed compensation namespace must fail at replay classification: {detail_chirho}"
        ),
        Err(error_chirho) => panic!("unexpected replay refusal: {error_chirho:?}"),
        Ok(_) => panic!("malformed compensation prefix must fail load closed"),
    }
}
