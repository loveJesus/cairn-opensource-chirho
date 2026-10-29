// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! CF3 terminal-door proofs: one terminal coordinate, provider-committed finalize+meter,
//! definite-no-effect release, current-policy continuation, stale/manual refusal, checkpoint
//! carriage, and the chain-valid conflicting-terminal replay twin.

use crate::admission_chirho::*;
use crate::checkpoint_chirho::{
    canonical_head_checkpoint_bytes_chirho, parse_head_checkpoint_chirho,
};
use crate::journal_chirho::*;
use crate::journal_tests_chirho::{
    mint_request_chirho, transfer_request_chirho, HarnessChirho, MONEY_KIND_CHIRHO,
    MONEY_POLICY_REF_CHIRHO,
};
use crate::ports_chirho::{LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho};
use anyhow::Result;
use cairn_effect_commit_chirho::intent_chirho::*;
use cairn_effect_commit_chirho::terminal_chirho::*;
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, AssetKindRefChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::AttributionChirho;
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_record_line_chirho, ledger_record_signed_content_line_chirho,
    parse_canonical_ledger_journal_line_chirho, stored_line_digest_chirho, LedgerJournalLineChirho,
};
use cairn_ledger_model_chirho::LogIdChirho;
use std::cell::Cell;

const POLICY_V2_CHIRHO: &str = "policy-money-v2-chirho";
pub(crate) const DIGEST_A_CHIRHO: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub(crate) const DIGEST_B_CHIRHO: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
pub(crate) const DIGEST_C_CHIRHO: &str =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
pub(crate) const DIGEST_D_CHIRHO: &str =
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
pub(crate) const DIGEST_E_CHIRHO: &str =
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
pub(crate) const DIGEST_F_CHIRHO: &str =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

pub(crate) struct FakeEffectRootChirho {
    pub(crate) root_chirho: &'static str,
}

impl EffectIntentSignerPortChirho for FakeEffectRootChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(root_signature_chirho(
            self.root_chirho,
            signed_content_line_chirho,
        ))
    }

    fn key_id_chirho(&self) -> String {
        format!("{}-key-chirho", self.root_chirho)
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == root_signature_chirho(self.root_chirho, signed_content_line_chirho)
    }
}

impl EffectTerminalSignerPortChirho for FakeEffectRootChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(root_signature_chirho(
            self.root_chirho,
            signed_content_line_chirho,
        ))
    }

    fn key_id_chirho(&self) -> String {
        format!("{}-key-chirho", self.root_chirho)
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == root_signature_chirho(self.root_chirho, signed_content_line_chirho)
    }
}

fn root_signature_chirho(root_chirho: &str, content_chirho: &str) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(root_chirho.as_bytes());
    hasher_chirho.update(content_chirho.as_bytes());
    hasher_chirho.finalize().to_hex().to_string()
}

pub(crate) fn digest_chirho(value_chirho: &str) -> DigestChirho {
    DigestChirho(value_chirho.to_owned())
}

pub(crate) fn funded_engine_chirho<'harness_chirho>(
    harness_chirho: &'harness_chirho HarnessChirho,
) -> LedgerJournalChirho<'harness_chirho> {
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            500,
            "terminal-mint-chirho",
        ))
        .unwrap();
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            100,
            "terminal-fund-chirho",
        ))
        .unwrap();
    engine_chirho
}

pub(crate) fn signed_intent_chirho(
    engine_chirho: &LedgerJournalChirho<'_>,
    root_chirho: &FakeEffectRootChirho,
    policy_ref_chirho: &str,
) -> (EffectIntentChirho, String) {
    let intent_chirho = sign_effect_intent_chirho(
        EffectIntentChirho {
            schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
            journal_cut_chirho: engine_chirho.effect_intent_cut_chirho(),
            contract_set_digest_chirho: digest_chirho(DIGEST_A_CHIRHO),
            door_chirho: serde_json::from_value(serde_json::json!({
                "effect_node_chirho": DIGEST_B_CHIRHO,
                "capability_fingerprint_chirho": DIGEST_C_CHIRHO,
            }))
            .unwrap(),
            reversion_contract_digest_chirho: digest_chirho(DIGEST_D_CHIRHO),
            request_ref_chirho: digest_chirho(DIGEST_E_CHIRHO),
            request_context_ref_chirho: digest_chirho(DIGEST_F_CHIRHO),
            evidence_refs_chirho: vec![digest_chirho(DIGEST_A_CHIRHO)],
            resolved_price_chirho: AssetOpChirho {
                amount_chirho: 10,
                kind_id_chirho: AssetKindIdChirho(MONEY_KIND_CHIRHO.to_owned()),
                kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                    policy_ref_chirho.to_owned(),
                )),
                rounding_chirho: RoundingChirho::ExactChirho,
            },
            payer_account_chirho: LogIdChirho::new_chirho("alice-chirho", MONEY_KIND_CHIRHO),
            effect_step_chirho: 3,
            attribution_chirho: AttributionChirho::CauserChirho {
                principal_chirho: "alice-chirho".to_owned(),
            },
            original_effect_key_chirho: None,
            sig_chirho: String::new(),
            key_id_chirho: String::new(),
        },
        root_chirho,
    )
    .unwrap();
    let line_chirho = canonical_effect_intent_line_chirho(&intent_chirho).unwrap();
    (intent_chirho, line_chirho)
}

pub(crate) fn signed_terminal_line_chirho(
    intent_chirho: &EffectIntentChirho,
    root_chirho: &FakeEffectRootChirho,
    disposition_chirho: EffectTerminalDispositionChirho,
    provider_evidence_ref_chirho: &str,
) -> String {
    let outcome_chirho = sign_effect_terminal_outcome_chirho(
        EffectTerminalOutcomeChirho {
            schema_chirho: EFFECT_TERMINAL_OUTCOME_SCHEMA_V1_CHIRHO.to_owned(),
            intent_ref_chirho: effect_intent_ref_chirho(intent_chirho).unwrap(),
            provider_evidence_ref_chirho: digest_chirho(provider_evidence_ref_chirho),
            disposition_chirho,
            sig_chirho: String::new(),
            key_id_chirho: String::new(),
        },
        root_chirho,
    )
    .unwrap();
    canonical_effect_terminal_outcome_line_chirho(&outcome_chirho).unwrap()
}

#[test]
fn committed_terminal_finalizes_and_meters_once_across_fast_open_chirho() {
    let mut harness_chirho = HarnessChirho::new_chirho();
    harness_chirho.registry_chirho.settlement_owner_chirho = Some("bob-chirho".to_owned());
    let mut engine_chirho = funded_engine_chirho(&harness_chirho);
    let intent_root_chirho = FakeEffectRootChirho {
        root_chirho: "intent-root-chirho",
    };
    let terminal_root_chirho = FakeEffectRootChirho {
        root_chirho: "terminal-root-chirho",
    };
    let (intent_chirho, intent_line_chirho) =
        signed_intent_chirho(&engine_chirho, &intent_root_chirho, MONEY_POLICY_REF_CHIRHO);
    let hold_receipt_chirho = engine_chirho
        .append_effect_intent_chirho(&intent_line_chirho, &intent_root_chirho)
        .unwrap();
    let terminal_line_chirho = signed_terminal_line_chirho(
        &intent_chirho,
        &terminal_root_chirho,
        EffectTerminalDispositionChirho::CommittedChirho {
            result_ref_chirho: digest_chirho(DIGEST_B_CHIRHO),
        },
        DIGEST_C_CHIRHO,
    );
    let terminal_receipt_chirho = engine_chirho
        .append_effect_terminal_chirho(
            &intent_line_chirho,
            &intent_root_chirho,
            &terminal_line_chirho,
            &terminal_root_chirho,
        )
        .unwrap();
    assert_eq!(
        engine_chirho
            .append_effect_terminal_chirho(
                &intent_line_chirho,
                &intent_root_chirho,
                &terminal_line_chirho,
                &terminal_root_chirho,
            )
            .expect("same terminal outcome returns its original receipt"),
        terminal_receipt_chirho
    );
    assert_eq!(
        engine_chirho
            .append_effect_intent_chirho(&intent_line_chirho, &intent_root_chirho)
            .expect("same-K Hold replay after terminalization returns the original receipt"),
        hold_receipt_chirho
    );
    let alice_chirho = engine_chirho
        .head_state_chirho(&LogIdChirho::new_chirho("alice-chirho", MONEY_KIND_CHIRHO))
        .unwrap();
    assert_eq!(alice_chirho.held_chirho, 0);
    assert_eq!(alice_chirho.debits_total_chirho, 10);
    let settlement_chirho = engine_chirho
        .head_state_chirho(&LogIdChirho::new_chirho("bob-chirho", MONEY_KIND_CHIRHO))
        .unwrap();
    assert_eq!(settlement_chirho.credits_total_chirho, 10);
    assert!(engine_chirho.active_effect_intent_refs_chirho().is_empty());
    let inventory_chirho = engine_chirho.verified_effect_receipt_inventory_chirho();
    assert_eq!(inventory_chirho.len(), 1);
    assert_eq!(
        inventory_chirho[0].intent_ref_chirho,
        effect_intent_ref_chirho(&intent_chirho).unwrap()
    );
    assert!(inventory_chirho[0].control_saga_id_chirho.is_none());
    assert_eq!(
        inventory_chirho[0].hold_receipt_chirho.seq_chirho,
        hold_receipt_chirho.seq_chirho
    );
    assert_eq!(
        inventory_chirho[0]
            .terminal_receipt_chirho
            .as_ref()
            .unwrap()
            .seq_chirho,
        terminal_receipt_chirho.seq_chirho
    );
    assert!(inventory_chirho[0].terminal_outcome_ref_chirho.is_some());

    let conflicting_line_chirho = signed_terminal_line_chirho(
        &intent_chirho,
        &terminal_root_chirho,
        EffectTerminalDispositionChirho::DefiniteNoEffectChirho,
        DIGEST_D_CHIRHO,
    );
    assert!(matches!(
        engine_chirho.append_effect_terminal_chirho(
            &intent_line_chirho,
            &intent_root_chirho,
            &conflicting_line_chirho,
            &terminal_root_chirho,
        ),
        Err(JournalErrorChirho::EffectTerminalConflictChirho { .. })
    ));

    engine_chirho.write_head_checkpoint_chirho().unwrap();
    let sidecar_path_chirho = StoragePathChirho(format!(
        "{}.head-checkpoint-chirho",
        harness_chirho.path_chirho().0
    ));
    let checkpoint_bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&sidecar_path_chirho)
        .unwrap();
    assert!(!String::from_utf8(checkpoint_bytes_chirho.clone().unwrap())
        .unwrap()
        .contains("control_saga_id_chirho"));
    let mut checkpoint_chirho = parse_head_checkpoint_chirho(
        checkpoint_bytes_chirho
            .as_deref()
            .expect("checkpoint must exist after explicit write"),
    )
    .unwrap();
    assert!(checkpoint_chirho
        .effect_receipt_window_chirho
        .values()
        .all(|entry_chirho| entry_chirho.terminal_outcome_ref_chirho.is_some()));
    assert!(checkpoint_chirho
        .effect_receipt_window_chirho
        .values()
        .all(|entry_chirho| entry_chirho.terminal_receipt_chirho.is_some()));

    // Synthesize the signed pre-dual-receipt terminal shape: the old sidecar overwrote the Hold
    // coordinates with the terminal receipt and had no second slot. New code must discard this
    // advisory state, recover both receipts from the verified walk, then heal on the next write.
    let old_entry_chirho = checkpoint_chirho
        .effect_receipt_window_chirho
        .values_mut()
        .next()
        .expect("terminalized checkpoint carries one effect receipt");
    let old_terminal_receipt_chirho = old_entry_chirho
        .terminal_receipt_chirho
        .take()
        .expect("new checkpoint carries terminal coordinates");
    old_entry_chirho.committed_seq_chirho = old_terminal_receipt_chirho.seq_chirho;
    old_entry_chirho.committed_hlc_chirho = old_terminal_receipt_chirho.hlc_chirho;
    old_entry_chirho.stored_record_digest_chirho =
        old_terminal_receipt_chirho.stored_record_digest_chirho;
    checkpoint_chirho.sig_chirho.clear();
    let old_signing_line_chirho = String::from_utf8(
        checkpoint_chirho
            .signing_message_chirho()
            .expect("old-format checkpoint sign message remains canonical"),
    )
    .unwrap();
    checkpoint_chirho.sig_chirho = harness_chirho
        .signer_chirho
        .sign_chirho(&old_signing_line_chirho)
        .unwrap();
    let old_checkpoint_bytes_chirho =
        canonical_head_checkpoint_bytes_chirho(&checkpoint_chirho).unwrap();
    assert!(!String::from_utf8(old_checkpoint_bytes_chirho.clone())
        .unwrap()
        .contains("terminal_receipt_chirho"));
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&sidecar_path_chirho, &old_checkpoint_bytes_chirho)
        .unwrap();
    drop(engine_chirho);

    let mut migrated_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .unwrap();
    assert!(
        !migrated_chirho.last_open_was_fast_chirho(),
        "old terminalized sidecar falls back to the verified full replay"
    );
    assert_eq!(
        migrated_chirho
            .append_effect_intent_chirho(&intent_line_chirho, &intent_root_chirho)
            .unwrap(),
        hold_receipt_chirho
    );
    assert_eq!(
        migrated_chirho
            .append_effect_terminal_chirho(
                &intent_line_chirho,
                &intent_root_chirho,
                &terminal_line_chirho,
                &terminal_root_chirho,
            )
            .unwrap(),
        terminal_receipt_chirho
    );
    migrated_chirho.write_head_checkpoint_chirho().unwrap();
    drop(migrated_chirho);

    let mut reopened_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .unwrap();
    assert!(reopened_chirho.last_open_was_fast_chirho());
    assert_eq!(
        reopened_chirho
            .head_state_chirho(&LogIdChirho::new_chirho("bob-chirho", MONEY_KIND_CHIRHO))
            .unwrap()
            .credits_total_chirho,
        10
    );
    assert_eq!(
        reopened_chirho
            .append_effect_intent_chirho(&intent_line_chirho, &intent_root_chirho)
            .unwrap(),
        hold_receipt_chirho
    );
    assert_eq!(
        reopened_chirho
            .append_effect_terminal_chirho(
                &intent_line_chirho,
                &intent_root_chirho,
                &terminal_line_chirho,
                &terminal_root_chirho,
            )
            .unwrap(),
        terminal_receipt_chirho
    );
}

#[test]
fn dormant_current_cut_starts_terminal_finality_at_durable_hold_chirho() {
    let mut harness_chirho = HarnessChirho::new_chirho();
    harness_chirho.registry_chirho.settlement_owner_chirho = Some("bob-chirho".to_owned());
    let mut engine_chirho = funded_engine_chirho(&harness_chirho);

    harness_chirho.clock_chirho.now_ms_chirho.set(2_000);
    let intent_root_chirho = FakeEffectRootChirho {
        root_chirho: "intent-root-chirho",
    };
    let terminal_root_chirho = FakeEffectRootChirho {
        root_chirho: "terminal-root-chirho",
    };
    let (intent_chirho, intent_line_chirho) =
        signed_intent_chirho(&engine_chirho, &intent_root_chirho, MONEY_POLICY_REF_CHIRHO);
    assert_eq!(
        intent_chirho
            .journal_cut_chirho
            .tail_hlc_chirho
            .physical_ms_chirho,
        1_000
    );
    let hold_receipt_chirho = engine_chirho
        .append_effect_intent_chirho(&intent_line_chirho, &intent_root_chirho)
        .expect("an exact current cut remains admissible after journal idle");
    assert_eq!(hold_receipt_chirho.hlc_chirho.physical_ms_chirho, 2_000);

    let terminal_line_chirho = signed_terminal_line_chirho(
        &intent_chirho,
        &terminal_root_chirho,
        EffectTerminalDispositionChirho::CommittedChirho {
            result_ref_chirho: digest_chirho(DIGEST_B_CHIRHO),
        },
        DIGEST_C_CHIRHO,
    );
    let terminal_receipt_chirho = engine_chirho
        .append_effect_terminal_chirho(
            &intent_line_chirho,
            &intent_root_chirho,
            &terminal_line_chirho,
            &terminal_root_chirho,
        )
        .expect("idle before the Hold is not terminal delay");
    assert_eq!(
        terminal_receipt_chirho.seq_chirho,
        hold_receipt_chirho.seq_chirho + 1
    );

    let payer_chirho = engine_chirho
        .head_state_chirho(&LogIdChirho::new_chirho("alice-chirho", MONEY_KIND_CHIRHO))
        .unwrap();
    assert_eq!(payer_chirho.held_chirho, 0);
    assert_eq!(payer_chirho.debits_total_chirho, 10);
    let settlement_chirho = engine_chirho
        .head_state_chirho(&LogIdChirho::new_chirho("bob-chirho", MONEY_KIND_CHIRHO))
        .unwrap();
    assert_eq!(settlement_chirho.credits_total_chirho, 10);
}

#[test]
fn definite_no_effect_releases_without_metering_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = funded_engine_chirho(&harness_chirho);
    let intent_root_chirho = FakeEffectRootChirho {
        root_chirho: "intent-root-chirho",
    };
    let terminal_root_chirho = FakeEffectRootChirho {
        root_chirho: "terminal-root-chirho",
    };
    let (intent_chirho, intent_line_chirho) =
        signed_intent_chirho(&engine_chirho, &intent_root_chirho, MONEY_POLICY_REF_CHIRHO);
    engine_chirho
        .append_effect_intent_chirho(&intent_line_chirho, &intent_root_chirho)
        .unwrap();
    let terminal_line_chirho = signed_terminal_line_chirho(
        &intent_chirho,
        &terminal_root_chirho,
        EffectTerminalDispositionChirho::DefiniteNoEffectChirho,
        DIGEST_C_CHIRHO,
    );
    engine_chirho
        .append_effect_terminal_chirho(
            &intent_line_chirho,
            &intent_root_chirho,
            &terminal_line_chirho,
            &terminal_root_chirho,
        )
        .unwrap();
    let alice_chirho = engine_chirho
        .head_state_chirho(&LogIdChirho::new_chirho("alice-chirho", MONEY_KIND_CHIRHO))
        .unwrap();
    assert_eq!(alice_chirho.held_chirho, 0);
    assert_eq!(alice_chirho.debits_total_chirho, 0);
}

struct AmendingRegistryChirho {
    amended_chirho: Cell<bool>,
    wrong_kind_chirho: Cell<bool>,
}

impl AmendingRegistryChirho {
    fn policy_chirho(
        &self,
        settlement_owner_chirho: &str,
        kind_id_chirho: &str,
    ) -> KindPolicyViewChirho {
        KindPolicyViewChirho {
            kind_id_chirho: AssetKindIdChirho(kind_id_chirho.to_owned()),
            mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                max_supply_chirho: Some(1_000),
            },
            rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
            settlement_owner_chirho: Some(settlement_owner_chirho.to_owned()),
            idempotency_window_chirho: Some(IdempotencyWindowPolicyViewChirho {
                idempotency_horizon_ms_chirho: 1_000,
                retry_finality_horizon_ms_chirho: 500,
            }),
        }
    }
}

impl KindRegistryViewChirho for AmendingRegistryChirho {
    fn resolve_chirho(&self, policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        match (self.amended_chirho.get(), policy_ref_chirho.0 .0.as_str()) {
            (false, MONEY_POLICY_REF_CHIRHO) => KindResolutionChirho::CurrentChirho(
                self.policy_chirho("issuer-chirho", MONEY_KIND_CHIRHO),
            ),
            (true, MONEY_POLICY_REF_CHIRHO) => KindResolutionChirho::SupersededChirho,
            (true, POLICY_V2_CHIRHO) => KindResolutionChirho::CurrentChirho(
                self.policy_chirho("bob-chirho", MONEY_KIND_CHIRHO),
            ),
            _ => KindResolutionChirho::UnknownChirho,
        }
    }

    fn resolve_recorded_ref_retention_window_chirho(
        &self,
        policy_ref_chirho: &AssetKindRefChirho,
    ) -> RecordedRetentionWindowChirho {
        if matches!(
            policy_ref_chirho.0 .0.as_str(),
            MONEY_POLICY_REF_CHIRHO | POLICY_V2_CHIRHO
        ) {
            RecordedRetentionWindowChirho::BoundedChirho(IdempotencyWindowPolicyViewChirho {
                idempotency_horizon_ms_chirho: 1_000,
                retry_finality_horizon_ms_chirho: 500,
            })
        } else {
            RecordedRetentionWindowChirho::RetainIndefinitelyChirho
        }
    }

    fn resolve_current_continuation_by_kind_chirho(
        &self,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> Option<CurrentContinuationPolicyChirho> {
        (kind_id_chirho.0 == MONEY_KIND_CHIRHO).then(|| {
            let amended_chirho = self.amended_chirho.get();
            CurrentContinuationPolicyChirho {
                kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                    if amended_chirho {
                        POLICY_V2_CHIRHO
                    } else {
                        MONEY_POLICY_REF_CHIRHO
                    }
                    .to_owned(),
                )),
                policy_chirho: self.policy_chirho(
                    if amended_chirho {
                        "bob-chirho"
                    } else {
                        "issuer-chirho"
                    },
                    if self.wrong_kind_chirho.get() {
                        "other-kind-chirho"
                    } else {
                        MONEY_KIND_CHIRHO
                    },
                ),
            }
        })
    }
}

#[test]
fn r1_hold_terminalizes_under_r2_and_credits_r2_settlement_owner_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let registry_chirho = AmendingRegistryChirho {
        amended_chirho: Cell::new(false),
        wrong_kind_chirho: Cell::new(false),
    };
    let ports_chirho = JournalPortsChirho {
        kind_registry_chirho: &registry_chirho,
        ..harness_chirho.ports_chirho()
    };
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        ports_chirho,
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    engine_chirho
        .append_chirho(mint_request_chirho("issuer-chirho", 500, "r2-mint-chirho"))
        .unwrap();
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            100,
            "r2-fund-chirho",
        ))
        .unwrap();
    let intent_root_chirho = FakeEffectRootChirho {
        root_chirho: "intent-root-chirho",
    };
    let terminal_root_chirho = FakeEffectRootChirho {
        root_chirho: "terminal-root-chirho",
    };
    let (intent_chirho, intent_line_chirho) =
        signed_intent_chirho(&engine_chirho, &intent_root_chirho, MONEY_POLICY_REF_CHIRHO);
    engine_chirho
        .append_effect_intent_chirho(&intent_line_chirho, &intent_root_chirho)
        .unwrap();
    registry_chirho.amended_chirho.set(true);
    let terminal_line_chirho = signed_terminal_line_chirho(
        &intent_chirho,
        &terminal_root_chirho,
        EffectTerminalDispositionChirho::CommittedChirho {
            result_ref_chirho: digest_chirho(DIGEST_B_CHIRHO),
        },
        DIGEST_C_CHIRHO,
    );
    engine_chirho
        .append_effect_terminal_chirho(
            &intent_line_chirho,
            &intent_root_chirho,
            &terminal_line_chirho,
            &terminal_root_chirho,
        )
        .unwrap();
    assert_eq!(
        engine_chirho
            .head_state_chirho(&LogIdChirho::new_chirho("bob-chirho", MONEY_KIND_CHIRHO))
            .unwrap()
            .credits_total_chirho,
        10
    );
    assert_eq!(
        engine_chirho
            .head_state_chirho(&LogIdChirho::new_chirho("alice-chirho", MONEY_KIND_CHIRHO))
            .unwrap()
            .held_chirho,
        0
    );
}

#[test]
fn wrong_current_kind_and_past_horizon_terminal_both_leave_hold_live_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let registry_chirho = AmendingRegistryChirho {
        amended_chirho: Cell::new(false),
        wrong_kind_chirho: Cell::new(false),
    };
    let ports_chirho = JournalPortsChirho {
        kind_registry_chirho: &registry_chirho,
        ..harness_chirho.ports_chirho()
    };
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        ports_chirho,
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            500,
            "negative-mint-chirho",
        ))
        .unwrap();
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            100,
            "negative-fund-chirho",
        ))
        .unwrap();
    let intent_root_chirho = FakeEffectRootChirho {
        root_chirho: "intent-root-chirho",
    };
    let terminal_root_chirho = FakeEffectRootChirho {
        root_chirho: "terminal-root-chirho",
    };
    let (intent_chirho, intent_line_chirho) =
        signed_intent_chirho(&engine_chirho, &intent_root_chirho, MONEY_POLICY_REF_CHIRHO);
    let intent_ref_chirho = effect_intent_ref_chirho(&intent_chirho).unwrap();
    engine_chirho
        .append_effect_intent_chirho(&intent_line_chirho, &intent_root_chirho)
        .unwrap();
    let terminal_line_chirho = signed_terminal_line_chirho(
        &intent_chirho,
        &terminal_root_chirho,
        EffectTerminalDispositionChirho::DefiniteNoEffectChirho,
        DIGEST_C_CHIRHO,
    );

    registry_chirho.wrong_kind_chirho.set(true);
    let tail_before_chirho = engine_chirho.tail_seq_chirho();
    assert!(matches!(
        engine_chirho.append_effect_terminal_chirho(
            &intent_line_chirho,
            &intent_root_chirho,
            &terminal_line_chirho,
            &terminal_root_chirho,
        ),
        Err(JournalErrorChirho::EffectTerminalChirho { .. })
    ));
    assert_eq!(engine_chirho.tail_seq_chirho(), tail_before_chirho);
    registry_chirho.wrong_kind_chirho.set(false);

    harness_chirho.clock_chirho.now_ms_chirho.set(2_000);
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            1,
            "advance-terminal-age-chirho",
        ))
        .unwrap();
    assert!(matches!(
        engine_chirho.append_effect_terminal_chirho(
            &intent_line_chirho,
            &intent_root_chirho,
            &terminal_line_chirho,
            &terminal_root_chirho,
        ),
        Err(JournalErrorChirho::StaleEffectTerminalChirho { .. })
    ));
    assert_eq!(
        engine_chirho.active_effect_intent_refs_chirho(),
        vec![intent_ref_chirho]
    );
    let payer_chirho = engine_chirho
        .head_state_chirho(&LogIdChirho::new_chirho("alice-chirho", MONEY_KIND_CHIRHO))
        .unwrap();
    assert_eq!(payer_chirho.held_chirho, 10);
    assert_eq!(payer_chirho.debits_total_chirho, 0);
}

#[test]
fn chain_valid_conflicting_terminal_fails_load_before_fold_chirho() {
    let mut harness_chirho = HarnessChirho::new_chirho();
    harness_chirho.registry_chirho.settlement_owner_chirho = Some("bob-chirho".to_owned());
    let mut engine_chirho = funded_engine_chirho(&harness_chirho);
    let intent_root_chirho = FakeEffectRootChirho {
        root_chirho: "intent-root-chirho",
    };
    let terminal_root_chirho = FakeEffectRootChirho {
        root_chirho: "terminal-root-chirho",
    };
    let (intent_chirho, intent_line_chirho) =
        signed_intent_chirho(&engine_chirho, &intent_root_chirho, MONEY_POLICY_REF_CHIRHO);
    engine_chirho
        .append_effect_intent_chirho(&intent_line_chirho, &intent_root_chirho)
        .unwrap();
    let terminal_line_chirho = signed_terminal_line_chirho(
        &intent_chirho,
        &terminal_root_chirho,
        EffectTerminalDispositionChirho::CommittedChirho {
            result_ref_chirho: digest_chirho(DIGEST_B_CHIRHO),
        },
        DIGEST_C_CHIRHO,
    );
    engine_chirho
        .append_effect_terminal_chirho(
            &intent_line_chirho,
            &intent_root_chirho,
            &terminal_line_chirho,
            &terminal_root_chirho,
        )
        .unwrap();

    let journal_bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&harness_chirho.path_chirho())
        .unwrap();
    let text_chirho = String::from_utf8(
        journal_bytes_chirho.expect("active journal must exist after terminal append"),
    )
    .unwrap();
    let last_line_chirho = text_chirho.lines().last().unwrap();
    let mut forged_chirho =
        match parse_canonical_ledger_journal_line_chirho(last_line_chirho).unwrap() {
            LedgerJournalLineChirho::RecordChirho(record_chirho) => record_chirho,
            LedgerJournalLineChirho::GenesisChirho(_) => panic!("terminal tail must be a record"),
        };
    forged_chirho.seq_chirho += 1;
    forged_chirho.prev_chirho = stored_line_digest_chirho(last_line_chirho);
    forged_chirho.hlc_chirho.logical_chirho += 1;
    forged_chirho.provenance_chirho = Some(digest_chirho(DIGEST_F_CHIRHO));
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

    assert!(matches!(
        LedgerJournalChirho::open_chirho(
            harness_chirho.ports_chirho(),
            harness_chirho.path_chirho(),
            &harness_chirho.cluster_chirho(),
        ),
        Err(JournalErrorChirho::EffectTerminalConflictChirho { .. })
    ));
}

#[test]
fn terminal_reserved_namespace_refuses_generic_append_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = funded_engine_chirho(&harness_chirho);
    let mut request_chirho = transfer_request_chirho(
        "issuer-chirho",
        "alice-chirho",
        1,
        "placeholder-terminal-key-chirho",
    );
    request_chirho.idempotency_key_chirho = format!("{EFFECT_TERMINAL_KEY_PREFIX_CHIRHO}XYZ");
    assert!(matches!(
        engine_chirho.append_chirho(request_chirho),
        Err(JournalErrorChirho::EffectTerminalChirho { .. })
    ));
}
