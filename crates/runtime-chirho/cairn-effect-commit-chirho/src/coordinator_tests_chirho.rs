// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::compensation_chirho::*;
use crate::coordinator_chirho::*;
use crate::intent_chirho::*;
use crate::terminal_chirho::*;
use anyhow::Result;
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, AssetKindRefChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, HlcChirho};
use cairn_ledger_model_chirho::LogIdChirho;
use cairn_undo_plan_chirho::plan_chirho::UndoDoorKeyChirho;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;

const DIGEST_A_CHIRHO: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B_CHIRHO: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_C_CHIRHO: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const DIGEST_D_CHIRHO: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const DIGEST_E_CHIRHO: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const DIGEST_F_CHIRHO: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

type EventLogChirho = Rc<RefCell<Vec<&'static str>>>;

struct FakeRootChirho {
    root_chirho: &'static str,
}

impl EffectIntentSignerPortChirho for FakeRootChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(signature_chirho(
            self.root_chirho,
            signed_content_line_chirho,
        ))
    }

    fn key_id_chirho(&self) -> String {
        format!("{}-key-chirho", self.root_chirho)
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == signature_chirho(self.root_chirho, signed_content_line_chirho)
    }
}

impl EffectTerminalSignerPortChirho for FakeRootChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(signature_chirho(
            self.root_chirho,
            signed_content_line_chirho,
        ))
    }

    fn key_id_chirho(&self) -> String {
        format!("{}-key-chirho", self.root_chirho)
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == signature_chirho(self.root_chirho, signed_content_line_chirho)
    }
}

fn signature_chirho(root_chirho: &str, content_chirho: &str) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(root_chirho.as_bytes());
    hasher_chirho.update(content_chirho.as_bytes());
    hasher_chirho.finalize().to_hex().to_string()
}

fn digest_chirho(value_chirho: &str) -> DigestChirho {
    DigestChirho(value_chirho.to_owned())
}

fn signed_intent_line_chirho(root_chirho: &FakeRootChirho) -> String {
    canonical_effect_intent_line_chirho(
        &sign_effect_intent_chirho(
            EffectIntentChirho {
                schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
                journal_cut_chirho: EffectIntentJournalCutChirho {
                    journal_genesis_digest_chirho: digest_chirho(DIGEST_A_CHIRHO),
                    tail_seq_chirho: 7,
                    tail_record_digest_chirho: digest_chirho(DIGEST_B_CHIRHO),
                    tail_hlc_chirho: HlcChirho {
                        physical_ms_chirho: 1_000,
                        logical_chirho: 0,
                    },
                },
                contract_set_digest_chirho: digest_chirho(DIGEST_C_CHIRHO),
                door_chirho: serde_json::from_value::<UndoDoorKeyChirho>(serde_json::json!({
                    "effect_node_chirho": DIGEST_D_CHIRHO,
                    "capability_fingerprint_chirho": DIGEST_E_CHIRHO,
                }))
                .unwrap(),
                reversion_contract_digest_chirho: digest_chirho(DIGEST_F_CHIRHO),
                request_ref_chirho: digest_chirho(DIGEST_A_CHIRHO),
                request_context_ref_chirho: digest_chirho(DIGEST_B_CHIRHO),
                evidence_refs_chirho: vec![digest_chirho(DIGEST_C_CHIRHO)],
                resolved_price_chirho: AssetOpChirho {
                    amount_chirho: 25,
                    kind_id_chirho: AssetKindIdChirho("billing-credit-chirho".to_owned()),
                    kind_policy_ref_chirho: AssetKindRefChirho(digest_chirho(DIGEST_D_CHIRHO)),
                    rounding_chirho: RoundingChirho::ExactChirho,
                },
                payer_account_chirho: LogIdChirho::new_chirho(
                    "payer-chirho",
                    "billing-credit-chirho",
                ),
                effect_step_chirho: 2,
                attribution_chirho: AttributionChirho::CauserChirho {
                    principal_chirho: "payer-chirho".to_owned(),
                },
                original_effect_key_chirho: None,
                sig_chirho: String::new(),
                key_id_chirho: String::new(),
            },
            root_chirho,
        )
        .unwrap(),
    )
    .unwrap()
}

fn receipt_chirho(seq_chirho: u64, digest_value_chirho: &str) -> EffectCommitJournalReceiptChirho {
    EffectCommitJournalReceiptChirho {
        seq_chirho,
        record_digest_chirho: digest_chirho(digest_value_chirho),
        hlc_chirho: HlcChirho {
            physical_ms_chirho: 1_000 + seq_chirho,
            logical_chirho: 0,
        },
    }
}

struct FakeProviderChirho {
    events_chirho: EventLogChirho,
    execute_chirho:
        VecDeque<Result<EffectProviderObservationChirho, EffectProviderPortErrorChirho>>,
    query_chirho: VecDeque<Result<EffectProviderObservationChirho, EffectProviderPortErrorChirho>>,
}

impl BlessedEffectProviderPortChirho for FakeProviderChirho {
    fn execute_or_replay_chirho(
        &mut self,
        _intent_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<EffectProviderObservationChirho, EffectProviderPortErrorChirho> {
        self.events_chirho.borrow_mut().push("provider-execute");
        self.execute_chirho
            .pop_front()
            .unwrap_or(Ok(EffectProviderObservationChirho::InDoubtChirho))
    }

    fn query_by_key_chirho(
        &mut self,
        _intent_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<EffectProviderObservationChirho, EffectProviderPortErrorChirho> {
        self.events_chirho.borrow_mut().push("provider-query");
        self.query_chirho
            .pop_front()
            .unwrap_or(Ok(EffectProviderObservationChirho::InDoubtChirho))
    }
}

struct FakeEvidenceChirho {
    events_chirho: EventLogChirho,
    intent_lines_chirho: BTreeMap<String, String>,
    compensation_lines_chirho: BTreeMap<String, String>,
    provider_bytes_chirho: BTreeMap<String, Vec<u8>>,
    terminal_lines_chirho: BTreeMap<String, String>,
    fail_provider_store_chirho: bool,
}

impl EffectCommitEvidencePortChirho for FakeEvidenceChirho {
    fn store_intent_line_chirho(
        &mut self,
        intent_ref_chirho: &DigestChirho,
        canonical_line_chirho: &str,
    ) -> Result<(), EffectEvidencePortErrorChirho> {
        self.events_chirho.borrow_mut().push("store-intent");
        if effect_intent_ref_chirho(
            &parse_canonical_effect_intent_line_chirho(canonical_line_chirho).unwrap(),
        )
        .unwrap()
            != *intent_ref_chirho
        {
            return Err(EffectEvidencePortErrorChirho::ConflictChirho {
                detail_chirho: "intent ref mismatch".to_owned(),
            });
        }
        insert_same_or_refuse_chirho(
            &mut self.intent_lines_chirho,
            &intent_ref_chirho.0,
            canonical_line_chirho.to_owned(),
        )
    }

    fn load_intent_line_chirho(
        &self,
        intent_ref_chirho: &DigestChirho,
    ) -> Result<Option<String>, EffectEvidencePortErrorChirho> {
        self.events_chirho.borrow_mut().push("load-intent");
        Ok(self.intent_lines_chirho.get(&intent_ref_chirho.0).cloned())
    }

    fn create_or_load_compensation_intent_line_chirho(
        &mut self,
        compensation_key_chirho: &str,
        intent_ref_chirho: &DigestChirho,
        canonical_line_chirho: &str,
    ) -> Result<String, EffectEvidencePortErrorChirho> {
        self.events_chirho
            .borrow_mut()
            .push("create-or-load-compensation-intent");
        if self
            .compensation_lines_chirho
            .get(compensation_key_chirho)
            .is_some_and(|existing_chirho| existing_chirho != canonical_line_chirho)
            || self
                .intent_lines_chirho
                .get(&intent_ref_chirho.0)
                .is_some_and(|existing_chirho| existing_chirho != canonical_line_chirho)
        {
            return Err(EffectEvidencePortErrorChirho::ConflictChirho {
                detail_chirho: "compensation K or intent ref already binds different evidence"
                    .to_owned(),
            });
        }
        self.intent_lines_chirho.insert(
            intent_ref_chirho.0.clone(),
            canonical_line_chirho.to_owned(),
        );
        self.compensation_lines_chirho.insert(
            compensation_key_chirho.to_owned(),
            canonical_line_chirho.to_owned(),
        );
        Ok(canonical_line_chirho.to_owned())
    }

    fn store_provider_evidence_chirho(
        &mut self,
        evidence_ref_chirho: &DigestChirho,
        evidence_bytes_chirho: &[u8],
    ) -> Result<(), EffectEvidencePortErrorChirho> {
        self.events_chirho
            .borrow_mut()
            .push("store-provider-evidence");
        if self.fail_provider_store_chirho {
            return Err(EffectEvidencePortErrorChirho::UnavailableChirho {
                detail_chirho: "injected cut".to_owned(),
            });
        }
        if effect_provider_evidence_ref_chirho(evidence_bytes_chirho) != *evidence_ref_chirho {
            return Err(EffectEvidencePortErrorChirho::ConflictChirho {
                detail_chirho: "provider evidence ref mismatch".to_owned(),
            });
        }
        insert_same_or_refuse_chirho(
            &mut self.provider_bytes_chirho,
            &evidence_ref_chirho.0,
            evidence_bytes_chirho.to_vec(),
        )
    }

    fn store_terminal_outcome_line_chirho(
        &mut self,
        outcome_ref_chirho: &DigestChirho,
        canonical_line_chirho: &str,
    ) -> Result<(), EffectEvidencePortErrorChirho> {
        self.events_chirho
            .borrow_mut()
            .push("store-terminal-outcome");
        if effect_terminal_outcome_ref_chirho(
            &parse_canonical_effect_terminal_outcome_line_chirho(canonical_line_chirho).unwrap(),
        )
        .unwrap()
            != *outcome_ref_chirho
        {
            return Err(EffectEvidencePortErrorChirho::ConflictChirho {
                detail_chirho: "terminal outcome ref mismatch".to_owned(),
            });
        }
        insert_same_or_refuse_chirho(
            &mut self.terminal_lines_chirho,
            &outcome_ref_chirho.0,
            canonical_line_chirho.to_owned(),
        )
    }
}

fn insert_same_or_refuse_chirho<T: Clone + PartialEq>(
    map_chirho: &mut BTreeMap<String, T>,
    key_chirho: &str,
    value_chirho: T,
) -> Result<(), EffectEvidencePortErrorChirho> {
    if let Some(existing_chirho) = map_chirho.get(key_chirho) {
        if existing_chirho != &value_chirho {
            return Err(EffectEvidencePortErrorChirho::ConflictChirho {
                detail_chirho: "content-addressed ref rebound".to_owned(),
            });
        }
        return Ok(());
    }
    map_chirho.insert(key_chirho.to_owned(), value_chirho);
    Ok(())
}

struct FakeJournalChirho {
    events_chirho: EventLogChirho,
    states_chirho: BTreeMap<String, EffectIntentJournalStateChirho>,
    active_chirho: BTreeSet<String>,
    compensation_refusal_chirho: Option<EffectCommitJournalPortErrorChirho>,
}

impl EffectCommitJournalPortChirho for FakeJournalChirho {
    fn append_hold_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho> {
        self.events_chirho.borrow_mut().push("append-hold");
        let intent_chirho = parse_canonical_effect_intent_line_chirho(canonical_intent_line_chirho)
            .map_err(
                |error_chirho| EffectCommitJournalPortErrorChirho::RefusedChirho {
                    detail_chirho: error_chirho.to_string(),
                },
            )?;
        let intent_ref_chirho = effect_intent_ref_chirho(&intent_chirho).unwrap();
        if let Some(state_chirho) = self.states_chirho.get(&intent_ref_chirho.0) {
            return Ok(state_chirho.receipt_chirho.clone());
        }
        let receipt_chirho = receipt_chirho(8, DIGEST_C_CHIRHO);
        self.states_chirho.insert(
            intent_ref_chirho.0.clone(),
            EffectIntentJournalStateChirho {
                intent_ref_chirho: intent_ref_chirho.clone(),
                receipt_chirho: receipt_chirho.clone(),
                terminal_outcome_ref_chirho: None,
            },
        );
        self.active_chirho.insert(intent_ref_chirho.0);
        Ok(receipt_chirho)
    }

    fn append_compensation_hold_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        _authorization_chirho: &VerifiedEffectCompensationChirho,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho> {
        if let Some(refusal_chirho) = self.compensation_refusal_chirho.take() {
            return Err(refusal_chirho);
        }
        self.append_hold_chirho(canonical_intent_line_chirho)
    }

    fn append_terminal_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        canonical_terminal_line_chirho: &str,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho> {
        self.events_chirho.borrow_mut().push("append-terminal");
        let intent_chirho = parse_canonical_effect_intent_line_chirho(canonical_intent_line_chirho)
            .map_err(
                |error_chirho| EffectCommitJournalPortErrorChirho::RefusedChirho {
                    detail_chirho: error_chirho.to_string(),
                },
            )?;
        let intent_ref_chirho = effect_intent_ref_chirho(&intent_chirho).unwrap();
        let outcome_chirho =
            parse_canonical_effect_terminal_outcome_line_chirho(canonical_terminal_line_chirho)
                .map_err(
                    |error_chirho| EffectCommitJournalPortErrorChirho::RefusedChirho {
                        detail_chirho: error_chirho.to_string(),
                    },
                )?;
        if outcome_chirho.intent_ref_chirho != intent_ref_chirho {
            return Err(EffectCommitJournalPortErrorChirho::ConflictChirho {
                detail_chirho: "terminal names another intent".to_owned(),
            });
        }
        let outcome_ref_chirho = effect_terminal_outcome_ref_chirho(&outcome_chirho).unwrap();
        let state_chirho = self
            .states_chirho
            .get_mut(&intent_ref_chirho.0)
            .ok_or_else(|| EffectCommitJournalPortErrorChirho::RefusedChirho {
                detail_chirho: "terminal has no Hold".to_owned(),
            })?;
        if let Some(existing_chirho) = &state_chirho.terminal_outcome_ref_chirho {
            if existing_chirho != &outcome_ref_chirho {
                return Err(EffectCommitJournalPortErrorChirho::ConflictChirho {
                    detail_chirho: "conflicting terminal outcome".to_owned(),
                });
            }
            return Ok(state_chirho.receipt_chirho.clone());
        }
        state_chirho.receipt_chirho = receipt_chirho(9, DIGEST_D_CHIRHO);
        state_chirho.terminal_outcome_ref_chirho = Some(outcome_ref_chirho);
        self.active_chirho.remove(&intent_ref_chirho.0);
        Ok(state_chirho.receipt_chirho.clone())
    }

    fn active_hold_intent_refs_chirho(
        &self,
    ) -> Result<Vec<DigestChirho>, EffectCommitJournalPortErrorChirho> {
        self.events_chirho.borrow_mut().push("list-active");
        Ok(self
            .active_chirho
            .iter()
            .cloned()
            .map(DigestChirho)
            .collect())
    }

    fn receipt_by_intent_ref_chirho(
        &self,
        intent_ref_chirho: &DigestChirho,
    ) -> Result<Option<EffectIntentJournalStateChirho>, EffectCommitJournalPortErrorChirho> {
        self.events_chirho.borrow_mut().push("lookup-receipt");
        Ok(self.states_chirho.get(&intent_ref_chirho.0).cloned())
    }
}

fn committed_observation_chirho() -> EffectProviderObservationChirho {
    EffectProviderObservationChirho::CommittedChirho {
        result_ref_chirho: digest_chirho(DIGEST_E_CHIRHO),
        evidence_chirho: EffectProviderEvidenceBytesChirho::new_chirho(
            b"private-provider-commit-evidence-chirho".to_vec(),
        )
        .unwrap(),
    }
}

fn evidence_chirho(events_chirho: &EventLogChirho) -> FakeEvidenceChirho {
    FakeEvidenceChirho {
        events_chirho: Rc::clone(events_chirho),
        intent_lines_chirho: BTreeMap::new(),
        compensation_lines_chirho: BTreeMap::new(),
        provider_bytes_chirho: BTreeMap::new(),
        terminal_lines_chirho: BTreeMap::new(),
        fail_provider_store_chirho: false,
    }
}

fn journal_chirho(events_chirho: &EventLogChirho) -> FakeJournalChirho {
    FakeJournalChirho {
        events_chirho: Rc::clone(events_chirho),
        states_chirho: BTreeMap::new(),
        active_chirho: BTreeSet::new(),
        compensation_refusal_chirho: None,
    }
}

#[test]
fn committed_effect_orders_intent_hold_provider_evidence_then_terminal_chirho() {
    let events_chirho = Rc::new(RefCell::new(Vec::new()));
    let intent_root_chirho = FakeRootChirho {
        root_chirho: "intent-root-chirho",
    };
    let terminal_root_chirho = FakeRootChirho {
        root_chirho: "terminal-root-chirho",
    };
    let intent_line_chirho = signed_intent_line_chirho(&intent_root_chirho);
    let mut provider_chirho = FakeProviderChirho {
        events_chirho: Rc::clone(&events_chirho),
        execute_chirho: VecDeque::from([Ok(committed_observation_chirho())]),
        query_chirho: VecDeque::new(),
    };
    let mut evidence_chirho = evidence_chirho(&events_chirho);
    let mut journal_chirho = journal_chirho(&events_chirho);
    let result_chirho = EffectCommitCoordinatorChirho::new_chirho(
        &mut provider_chirho,
        &mut evidence_chirho,
        &mut journal_chirho,
        &intent_root_chirho,
        &terminal_root_chirho,
    )
    .execute_chirho(&intent_line_chirho)
    .unwrap();

    assert!(matches!(
        result_chirho,
        EffectCommitRunResultChirho::TerminalChirho {
            disposition_chirho: EffectTerminalDispositionChirho::CommittedChirho { .. },
            ..
        }
    ));
    assert_eq!(
        events_chirho.borrow().as_slice(),
        [
            "store-intent",
            "append-hold",
            "provider-execute",
            "store-provider-evidence",
            "store-terminal-outcome",
            "append-terminal",
        ]
    );
    assert!(journal_chirho.active_chirho.is_empty());
}

#[test]
fn provider_error_queries_same_key_and_terminalizes_committed_once_chirho() {
    let events_chirho = Rc::new(RefCell::new(Vec::new()));
    let intent_root_chirho = FakeRootChirho {
        root_chirho: "intent-root-chirho",
    };
    let terminal_root_chirho = FakeRootChirho {
        root_chirho: "terminal-root-chirho",
    };
    let intent_line_chirho = signed_intent_line_chirho(&intent_root_chirho);
    let mut provider_chirho = FakeProviderChirho {
        events_chirho: Rc::clone(&events_chirho),
        execute_chirho: VecDeque::from([Err(EffectProviderPortErrorChirho::UnavailableChirho {
            detail_chirho: "timeout after provider commit".to_owned(),
        })]),
        query_chirho: VecDeque::from([Ok(committed_observation_chirho())]),
    };
    let mut evidence_chirho = evidence_chirho(&events_chirho);
    let mut journal_chirho = journal_chirho(&events_chirho);
    let result_chirho = EffectCommitCoordinatorChirho::new_chirho(
        &mut provider_chirho,
        &mut evidence_chirho,
        &mut journal_chirho,
        &intent_root_chirho,
        &terminal_root_chirho,
    )
    .execute_chirho(&intent_line_chirho)
    .unwrap();
    assert!(matches!(
        result_chirho,
        EffectCommitRunResultChirho::TerminalChirho {
            disposition_chirho: EffectTerminalDispositionChirho::CommittedChirho { .. },
            ..
        }
    ));
    assert!(journal_chirho.active_chirho.is_empty());
    assert_eq!(
        events_chirho.borrow().as_slice(),
        [
            "store-intent",
            "append-hold",
            "provider-execute",
            "provider-query",
            "store-provider-evidence",
            "store-terminal-outcome",
            "append-terminal",
        ]
    );
}

#[test]
fn provider_error_and_unresolved_query_leave_hold_until_fsck_chirho() {
    let events_chirho = Rc::new(RefCell::new(Vec::new()));
    let intent_root_chirho = FakeRootChirho {
        root_chirho: "intent-root-chirho",
    };
    let terminal_root_chirho = FakeRootChirho {
        root_chirho: "terminal-root-chirho",
    };
    let intent_line_chirho = signed_intent_line_chirho(&intent_root_chirho);
    let mut provider_chirho = FakeProviderChirho {
        events_chirho: Rc::clone(&events_chirho),
        execute_chirho: VecDeque::from([Err(EffectProviderPortErrorChirho::UnavailableChirho {
            detail_chirho: "timeout after provider commit".to_owned(),
        })]),
        query_chirho: VecDeque::from([
            Err(EffectProviderPortErrorChirho::UnavailableChirho {
                detail_chirho: "query remains unavailable".to_owned(),
            }),
            Ok(committed_observation_chirho()),
        ]),
    };
    let mut evidence_chirho = evidence_chirho(&events_chirho);
    let mut journal_chirho = journal_chirho(&events_chirho);
    let mut coordinator_chirho = EffectCommitCoordinatorChirho::new_chirho(
        &mut provider_chirho,
        &mut evidence_chirho,
        &mut journal_chirho,
        &intent_root_chirho,
        &terminal_root_chirho,
    );
    let intent_ref_chirho = match coordinator_chirho
        .execute_chirho(&intent_line_chirho)
        .unwrap()
    {
        EffectCommitRunResultChirho::InDoubtChirho {
            intent_ref_chirho, ..
        } => intent_ref_chirho,
        other_chirho => panic!("expected unresolved provider result, got {other_chirho:?}"),
    };
    assert!(matches!(
        coordinator_chirho
            .reconcile_in_doubt_chirho(intent_ref_chirho)
            .unwrap(),
        EffectCommitRunResultChirho::TerminalChirho {
            disposition_chirho: EffectTerminalDispositionChirho::CommittedChirho { .. },
            ..
        }
    ));
    assert!(journal_chirho.active_chirho.is_empty());
    assert_eq!(
        events_chirho
            .borrow()
            .iter()
            .filter(|event_chirho| **event_chirho == "provider-query")
            .count(),
        2
    );
}

#[test]
fn definite_no_effect_is_the_only_provider_path_to_release_terminal_chirho() {
    let events_chirho = Rc::new(RefCell::new(Vec::new()));
    let intent_root_chirho = FakeRootChirho {
        root_chirho: "intent-root-chirho",
    };
    let terminal_root_chirho = FakeRootChirho {
        root_chirho: "terminal-root-chirho",
    };
    let mut provider_chirho = FakeProviderChirho {
        events_chirho: Rc::clone(&events_chirho),
        execute_chirho: VecDeque::from([Err(EffectProviderPortErrorChirho::UnavailableChirho {
            detail_chirho: "execute result unavailable".to_owned(),
        })]),
        query_chirho: VecDeque::from([Ok(
            EffectProviderObservationChirho::DefiniteNoEffectChirho {
                evidence_chirho: EffectProviderEvidenceBytesChirho::new_chirho(
                    b"definite-no-effect-evidence-chirho".to_vec(),
                )
                .unwrap(),
            },
        )]),
    };
    let mut evidence_chirho = evidence_chirho(&events_chirho);
    let mut journal_chirho = journal_chirho(&events_chirho);
    let result_chirho = EffectCommitCoordinatorChirho::new_chirho(
        &mut provider_chirho,
        &mut evidence_chirho,
        &mut journal_chirho,
        &intent_root_chirho,
        &terminal_root_chirho,
    )
    .execute_chirho(&signed_intent_line_chirho(&intent_root_chirho))
    .unwrap();
    assert!(matches!(
        result_chirho,
        EffectCommitRunResultChirho::TerminalChirho {
            disposition_chirho: EffectTerminalDispositionChirho::DefiniteNoEffectChirho,
            ..
        }
    ));
}

#[test]
fn evidence_failure_after_provider_never_appends_terminal_or_releases_hold_chirho() {
    let events_chirho = Rc::new(RefCell::new(Vec::new()));
    let intent_root_chirho = FakeRootChirho {
        root_chirho: "intent-root-chirho",
    };
    let terminal_root_chirho = FakeRootChirho {
        root_chirho: "terminal-root-chirho",
    };
    let mut provider_chirho = FakeProviderChirho {
        events_chirho: Rc::clone(&events_chirho),
        execute_chirho: VecDeque::from([Ok(committed_observation_chirho())]),
        query_chirho: VecDeque::new(),
    };
    let mut evidence_chirho = evidence_chirho(&events_chirho);
    evidence_chirho.fail_provider_store_chirho = true;
    let mut journal_chirho = journal_chirho(&events_chirho);
    let result_chirho = EffectCommitCoordinatorChirho::new_chirho(
        &mut provider_chirho,
        &mut evidence_chirho,
        &mut journal_chirho,
        &intent_root_chirho,
        &terminal_root_chirho,
    )
    .execute_chirho(&signed_intent_line_chirho(&intent_root_chirho));
    assert!(matches!(
        result_chirho,
        Err(EffectCommitCoordinatorErrorChirho::EvidenceChirho { .. })
    ));
    assert_eq!(journal_chirho.active_chirho.len(), 1);
    assert!(!events_chirho.borrow().contains(&"append-terminal"));
}

#[test]
fn provider_evidence_shape_and_source_authority_guards_hold_chirho() {
    assert_eq!(
        EffectProviderEvidenceBytesChirho::new_chirho(Vec::new()),
        Err(EffectProviderEvidenceShapeErrorChirho::EmptyChirho)
    );
    let source_chirho = include_str!("coordinator_chirho.rs");
    for forbidden_chirho in ["std::fs", "std::env", "env::var", "std::net"] {
        assert!(
            !source_chirho.contains(forbidden_chirho),
            "effect coordinator gained ambient authority token {forbidden_chirho}"
        );
    }
}

struct FakeCacheVerifierChirho {
    accept_chirho: bool,
}

impl EffectCacheHitVerifierPortChirho for FakeCacheVerifierChirho {
    fn verify_chirho(
        &self,
        intent_chirho: &VerifiedEffectIntentChirho,
        result_ref_chirho: &DigestChirho,
        evidence_bytes_chirho: &[u8],
    ) -> bool {
        self.accept_chirho
            && intent_chirho.intent_chirho().request_ref_chirho == digest_chirho(DIGEST_A_CHIRHO)
            && result_ref_chirho == &digest_chirho(DIGEST_E_CHIRHO)
            && evidence_bytes_chirho == b"verified-cache-evidence-chirho"
    }
}

fn cache_candidate_chirho() -> EffectCacheHitCandidateChirho {
    EffectCacheHitCandidateChirho::new_chirho(
        digest_chirho(DIGEST_E_CHIRHO),
        b"verified-cache-evidence-chirho".to_vec(),
    )
    .unwrap()
}

#[derive(Clone)]
struct FakeCompensationAuthorizationViewChirho {
    facts_chirho: CompensationAuthorizationFactsChirho,
}

impl CompensationAuthorizationViewChirho for FakeCompensationAuthorizationViewChirho {
    fn derive_chirho(
        &self,
        _candidate_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<CompensationAuthorizationFactsChirho, CompensationAuthorizationViewErrorChirho>
    {
        Ok(self.facts_chirho.clone())
    }
}

fn original_intent_key_chirho(root_chirho: &FakeRootChirho) -> String {
    verify_effect_intent_line_chirho(&signed_intent_line_chirho(root_chirho), root_chirho)
        .unwrap()
        .key_chirho()
        .to_owned()
}

fn signed_compensation_line_chirho(
    root_chirho: &FakeRootChirho,
    original_effect_key_chirho: String,
) -> String {
    let mut intent_chirho =
        parse_canonical_effect_intent_line_chirho(&signed_intent_line_chirho(root_chirho)).unwrap();
    intent_chirho.original_effect_key_chirho = Some(original_effect_key_chirho);
    canonical_effect_intent_line_chirho(
        &sign_effect_intent_chirho(intent_chirho, root_chirho).unwrap(),
    )
    .unwrap()
}

fn compensation_facts_chirho(
    original_effect_key_chirho: String,
    lineage_root_key_chirho: String,
    next_depth_chirho: u16,
    max_depth_chirho: u16,
    breaker_verdict_chirho: CompensationBreakerVerdictChirho,
) -> CompensationAuthorizationFactsChirho {
    CompensationAuthorizationFactsChirho::new_chirho(
        original_effect_key_chirho,
        lineage_root_key_chirho,
        next_depth_chirho,
        max_depth_chirho,
        breaker_verdict_chirho,
    )
}

#[test]
fn journal_authority_refusal_identities_survive_compensation_coordinator_chirho() {
    let identities_chirho = [
        EffectCommitJournalAuthorityRefusalIdentityChirho::SinkTermNoAcceptedWinnerChirho,
        EffectCommitJournalAuthorityRefusalIdentityChirho::SinkTermStaleWinnerChirho,
        EffectCommitJournalAuthorityRefusalIdentityChirho::SinkTermUnseenWinnerChirho,
        EffectCommitJournalAuthorityRefusalIdentityChirho::OrdinaryElectionSinkTermAcceptanceInputsUnavailableChirho,
        EffectCommitJournalAuthorityRefusalIdentityChirho::OrdinaryElectionSinkTermAcceptanceChirho,
    ];
    for identity_chirho in identities_chirho {
        let events_chirho = Rc::new(RefCell::new(Vec::new()));
        let intent_root_chirho = FakeRootChirho {
            root_chirho: "intent-root-chirho",
        };
        let terminal_root_chirho = FakeRootChirho {
            root_chirho: "terminal-root-chirho",
        };
        let original_key_chirho = original_intent_key_chirho(&intent_root_chirho);
        let line_chirho =
            signed_compensation_line_chirho(&intent_root_chirho, original_key_chirho.clone());
        let authorization_chirho = authorize_effect_compensation_chirho(
            &line_chirho,
            &intent_root_chirho,
            &FakeCompensationAuthorizationViewChirho {
                facts_chirho: compensation_facts_chirho(
                    original_key_chirho.clone(),
                    original_key_chirho,
                    1,
                    2,
                    CompensationBreakerVerdictChirho::PermittedChirho,
                ),
            },
        )
        .unwrap();
        let EffectCompensationAuthorizationOutcomeChirho::AuthorizedChirho(authorization_chirho) =
            authorization_chirho
        else {
            panic!("the exact fixture must authorize before the journal refusal");
        };
        let planted_private_detail_chirho =
            "/private/coordinator-authority-detail-needle-chirho".to_owned();
        let mut journal_chirho = journal_chirho(&events_chirho);
        journal_chirho.compensation_refusal_chirho =
            Some(EffectCommitJournalPortErrorChirho::AuthorityRefusedChirho {
                identity_chirho,
                detail_chirho: planted_private_detail_chirho.clone(),
            });
        let mut provider_chirho = FakeProviderChirho {
            events_chirho: Rc::clone(&events_chirho),
            execute_chirho: VecDeque::new(),
            query_chirho: VecDeque::new(),
        };
        let mut evidence_chirho = evidence_chirho(&events_chirho);

        let refusal_chirho = EffectCommitCoordinatorChirho::new_chirho(
            &mut provider_chirho,
            &mut evidence_chirho,
            &mut journal_chirho,
            &intent_root_chirho,
            &terminal_root_chirho,
        )
        .execute_compensation_chirho(&line_chirho, authorization_chirho)
        .expect_err("the journal authority refusal must stop before provider execution");
        let EffectCommitCoordinatorErrorChirho::JournalAuthorityRefusedChirho {
            identity_chirho: observed_identity_chirho,
            detail_chirho: observed_detail_chirho,
        } = refusal_chirho
        else {
            panic!("the coordinator must preserve the typed authority refusal: {refusal_chirho:?}");
        };
        assert_eq!(observed_identity_chirho, identity_chirho);
        assert_eq!(observed_detail_chirho, planted_private_detail_chirho);
        assert!(
            !events_chirho.borrow().contains(&"provider-execute"),
            "diagnostic preservation must not move or refire provider execution"
        );
    }
}

#[test]
fn compensation_depth_and_breaker_refuse_typed_before_a_door_token_exists_chirho() {
    let root_chirho = FakeRootChirho {
        root_chirho: "intent-root-chirho",
    };
    let original_key_chirho = original_intent_key_chirho(&root_chirho);
    let line_chirho = signed_compensation_line_chirho(&root_chirho, original_key_chirho.clone());

    let authorized_chirho = authorize_effect_compensation_chirho(
        &line_chirho,
        &root_chirho,
        &FakeCompensationAuthorizationViewChirho {
            facts_chirho: compensation_facts_chirho(
                original_key_chirho.clone(),
                original_key_chirho.clone(),
                1,
                2,
                CompensationBreakerVerdictChirho::PermittedChirho,
            ),
        },
    )
    .unwrap();
    let EffectCompensationAuthorizationOutcomeChirho::AuthorizedChirho(token_chirho) =
        authorized_chirho
    else {
        panic!("expected authorized compensation token");
    };
    assert_eq!(
        token_chirho.original_effect_key_chirho(),
        original_key_chirho
    );
    assert_eq!(token_chirho.next_depth_chirho(), 1);
    assert_eq!(token_chirho.max_depth_chirho(), 2);

    assert!(matches!(
        authorize_effect_compensation_chirho(
            &line_chirho,
            &root_chirho,
            &FakeCompensationAuthorizationViewChirho {
                facts_chirho: compensation_facts_chirho(
                    original_key_chirho.clone(),
                    original_key_chirho.clone(),
                    3,
                    2,
                    CompensationBreakerVerdictChirho::PermittedChirho,
                ),
            },
        )
        .unwrap(),
        EffectCompensationAuthorizationOutcomeChirho::PendingManualChirho(
            CompensationPendingManualChirho {
                reason_chirho: CompensationPendingReasonChirho::DepthExceededChirho { .. },
                ..
            }
        )
    ));
    assert!(matches!(
        authorize_effect_compensation_chirho(
            &line_chirho,
            &root_chirho,
            &FakeCompensationAuthorizationViewChirho {
                facts_chirho: compensation_facts_chirho(
                    original_key_chirho.clone(),
                    original_key_chirho,
                    1,
                    2,
                    CompensationBreakerVerdictChirho::TrippedChirho {
                        detail_chirho: "lineage breaker open".to_owned(),
                    },
                ),
            },
        )
        .unwrap(),
        EffectCompensationAuthorizationOutcomeChirho::PendingManualChirho(
            CompensationPendingManualChirho {
                reason_chirho: CompensationPendingReasonChirho::CircuitBreakerTrippedChirho { .. },
                ..
            }
        )
    ));
}

#[test]
fn nested_compensation_derives_one_chained_coordinate_and_respects_depth_chirho() {
    let root_chirho = FakeRootChirho {
        root_chirho: "intent-root-chirho",
    };
    let lineage_root_key_chirho = original_intent_key_chirho(&root_chirho);
    let first_compensation_key_chirho =
        effect_compensation_key_chirho(&lineage_root_key_chirho).unwrap();
    let nested_line_chirho =
        signed_compensation_line_chirho(&root_chirho, first_compensation_key_chirho.clone());
    let authorized_chirho = authorize_effect_compensation_chirho(
        &nested_line_chirho,
        &root_chirho,
        &FakeCompensationAuthorizationViewChirho {
            facts_chirho: compensation_facts_chirho(
                first_compensation_key_chirho.clone(),
                lineage_root_key_chirho.clone(),
                2,
                2,
                CompensationBreakerVerdictChirho::PermittedChirho,
            ),
        },
    )
    .unwrap();
    let EffectCompensationAuthorizationOutcomeChirho::AuthorizedChirho(token_chirho) =
        authorized_chirho
    else {
        panic!("expected nested authorization");
    };
    assert_eq!(
        token_chirho.compensation_key_chirho(),
        effect_compensation_key_chirho(&first_compensation_key_chirho).unwrap()
    );
    assert_eq!(
        token_chirho.lineage_root_key_chirho(),
        lineage_root_key_chirho
    );
    assert_eq!(token_chirho.next_depth_chirho(), 2);

    assert!(matches!(
        authorize_effect_compensation_chirho(
            &nested_line_chirho,
            &root_chirho,
            &FakeCompensationAuthorizationViewChirho {
                facts_chirho: compensation_facts_chirho(
                    first_compensation_key_chirho,
                    token_chirho.lineage_root_key_chirho().to_owned(),
                    3,
                    2,
                    CompensationBreakerVerdictChirho::PermittedChirho,
                ),
            },
        )
        .unwrap(),
        EffectCompensationAuthorizationOutcomeChirho::PendingManualChirho(
            CompensationPendingManualChirho {
                reason_chirho: CompensationPendingReasonChirho::DepthExceededChirho { .. },
                ..
            }
        )
    ));
}

#[test]
fn compensation_authority_cannot_swap_the_original_effect_binding_chirho() {
    let root_chirho = FakeRootChirho {
        root_chirho: "intent-root-chirho",
    };
    let original_key_chirho = original_intent_key_chirho(&root_chirho);
    let line_chirho = signed_compensation_line_chirho(&root_chirho, original_key_chirho.clone());
    let other_key_chirho = effect_compensation_key_chirho(&original_key_chirho).unwrap();
    assert!(matches!(
        authorize_effect_compensation_chirho(
            &line_chirho,
            &root_chirho,
            &FakeCompensationAuthorizationViewChirho {
                facts_chirho: compensation_facts_chirho(
                    other_key_chirho,
                    original_key_chirho,
                    1,
                    2,
                    CompensationBreakerVerdictChirho::PermittedChirho,
                ),
            },
        ),
        Err(EffectCompensationAuthorizationErrorChirho::FactBindingChirho { .. })
    ));
}

#[test]
fn unverified_cache_candidate_cannot_reach_hold_or_provider_chirho() {
    let events_chirho = Rc::new(RefCell::new(Vec::<&'static str>::new()));
    let intent_root_chirho = FakeRootChirho {
        root_chirho: "intent-root-chirho",
    };
    let intent_line_chirho = signed_intent_line_chirho(&intent_root_chirho);
    assert!(matches!(
        verify_effect_cache_hit_chirho(
            &intent_line_chirho,
            &intent_root_chirho,
            cache_candidate_chirho(),
            &FakeCacheVerifierChirho {
                accept_chirho: false,
            },
        ),
        Err(EffectCommitCoordinatorErrorChirho::CacheChirho { .. })
    ));
    assert!(events_chirho.borrow().is_empty());
}

#[test]
fn verified_cache_token_cannot_be_worn_by_another_signed_intent_chirho() {
    let events_chirho = Rc::new(RefCell::new(Vec::new()));
    let intent_root_chirho = FakeRootChirho {
        root_chirho: "intent-root-chirho",
    };
    let terminal_root_chirho = FakeRootChirho {
        root_chirho: "terminal-root-chirho",
    };
    let intent_line_chirho = signed_intent_line_chirho(&intent_root_chirho);
    let token_chirho = verify_effect_cache_hit_chirho(
        &intent_line_chirho,
        &intent_root_chirho,
        cache_candidate_chirho(),
        &FakeCacheVerifierChirho {
            accept_chirho: true,
        },
    )
    .unwrap();
    let mut other_intent_chirho = parse_canonical_effect_intent_line_chirho(&intent_line_chirho)
        .expect("fixture intent must parse");
    other_intent_chirho.request_ref_chirho = digest_chirho(DIGEST_B_CHIRHO);
    let other_intent_line_chirho = canonical_effect_intent_line_chirho(
        &sign_effect_intent_chirho(other_intent_chirho, &intent_root_chirho).unwrap(),
    )
    .unwrap();
    let mut provider_chirho = FakeProviderChirho {
        events_chirho: Rc::clone(&events_chirho),
        execute_chirho: VecDeque::new(),
        query_chirho: VecDeque::new(),
    };
    let mut evidence_chirho = evidence_chirho(&events_chirho);
    let mut journal_chirho = journal_chirho(&events_chirho);

    assert!(matches!(
        EffectCommitCoordinatorChirho::new_chirho(
            &mut provider_chirho,
            &mut evidence_chirho,
            &mut journal_chirho,
            &intent_root_chirho,
            &terminal_root_chirho,
        )
        .execute_verified_cache_hit_chirho(&other_intent_line_chirho, token_chirho),
        Err(EffectCommitCoordinatorErrorChirho::CacheChirho { .. })
    ));
    assert!(events_chirho.borrow().is_empty());
}

#[test]
fn verified_cache_hit_skips_provider_but_uses_same_meter_terminal_spine_chirho() {
    let events_chirho = Rc::new(RefCell::new(Vec::new()));
    let intent_root_chirho = FakeRootChirho {
        root_chirho: "intent-root-chirho",
    };
    let terminal_root_chirho = FakeRootChirho {
        root_chirho: "terminal-root-chirho",
    };
    let intent_line_chirho = signed_intent_line_chirho(&intent_root_chirho);
    let token_chirho = verify_effect_cache_hit_chirho(
        &intent_line_chirho,
        &intent_root_chirho,
        cache_candidate_chirho(),
        &FakeCacheVerifierChirho {
            accept_chirho: true,
        },
    )
    .unwrap();
    let mut provider_chirho = FakeProviderChirho {
        events_chirho: Rc::clone(&events_chirho),
        execute_chirho: VecDeque::new(),
        query_chirho: VecDeque::new(),
    };
    let mut evidence_chirho = evidence_chirho(&events_chirho);
    let mut journal_chirho = journal_chirho(&events_chirho);
    let result_chirho = EffectCommitCoordinatorChirho::new_chirho(
        &mut provider_chirho,
        &mut evidence_chirho,
        &mut journal_chirho,
        &intent_root_chirho,
        &terminal_root_chirho,
    )
    .execute_verified_cache_hit_chirho(&intent_line_chirho, token_chirho)
    .unwrap();

    assert!(matches!(
        result_chirho,
        EffectCommitRunResultChirho::TerminalChirho {
            disposition_chirho: EffectTerminalDispositionChirho::CommittedChirho { .. },
            ..
        }
    ));
    assert_eq!(
        events_chirho.borrow().as_slice(),
        [
            "store-intent",
            "append-hold",
            "store-provider-evidence",
            "store-terminal-outcome",
            "append-terminal",
        ]
    );
    assert!(!events_chirho.borrow().contains(&"provider-execute"));
    assert!(!events_chirho.borrow().contains(&"provider-query"));
    assert!(journal_chirho.active_chirho.is_empty());
}
