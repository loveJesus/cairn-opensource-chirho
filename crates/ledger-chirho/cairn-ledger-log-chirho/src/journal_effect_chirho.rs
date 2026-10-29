// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! CF3 intent and terminal journal doors plus the shared append/replay receipt transition.
//!
//! The terminal door derives every money coordinate from two verified authority objects: the
//! original intent and its one signed terminal outcome. Ordinary admission remains strict; an
//! already-admitted Hold continues under the registry's CURRENT policy resolved by stable kind.

use crate::admission_chirho::{EscrowHoldKeyChirho, RecordedRetentionWindowChirho};
use crate::checkpoint_chirho::{
    EffectReceiptWindowEntryChirho, EffectTerminalReceiptCoordinatesChirho,
};
use crate::effect_record_fact_chirho::{
    classify_effect_record_fact_chirho, EffectRecordFactChirho, EffectRecordFactRefusalChirho,
};
use crate::journal_chirho::{
    AppendIdempotencyClassChirho, AppendLegRequestChirho, AppendReceiptChirho, AppendRequestChirho,
    JournalErrorChirho, LedgerJournalChirho,
};
use cairn_effect_commit_chirho::compensation_chirho::VerifiedEffectCompensationChirho;
use cairn_effect_commit_chirho::coordinator_chirho::{
    EffectCommitJournalReceiptChirho, EffectIntentJournalStateChirho,
    VerifiedEffectReceiptInventoryEntryChirho,
};
use cairn_effect_commit_chirho::intent_chirho::{
    effect_compensation_key_chirho, parse_effect_compensation_key_chirho,
    parse_effect_intent_key_chirho, verify_effect_intent_line_chirho, EffectIntentChirho,
    EffectIntentSignerPortChirho, EFFECT_COMPENSATION_KEY_PREFIX_CHIRHO,
    EFFECT_INTENT_KEY_PREFIX_CHIRHO,
};
use cairn_effect_commit_chirho::terminal_chirho::{
    verify_effect_terminal_outcome_line_chirho, EffectTerminalDispositionChirho,
    EffectTerminalSignerPortChirho,
};
use cairn_ledger_model_chirho::ids_chirho::{AccountIdChirho, AssetKindRefChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::{
    EscrowControlChirho, LedgerOpChirho, LedgerRecordChirho, LegDeltaChirho,
};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EffectReceiptTransitionChirho {
    LegacyUnprunedChirho,
    IntentChirho {
        intent_ref_chirho: DigestChirho,
        control_saga_id_chirho: DigestChirho,
        policy_refs_chirho: Vec<AssetKindRefChirho>,
    },
    TerminalChirho {
        receipt_key_chirho: String,
        intent_ref_chirho: DigestChirho,
        control_saga_id_chirho: DigestChirho,
        outcome_ref_chirho: DigestChirho,
        policy_refs_chirho: Vec<AssetKindRefChirho>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectCompensationJournalErrorChirho {
    IntentConflictChirho {
        key_chirho: String,
        existing_intent_ref_chirho: DigestChirho,
        attempted_intent_ref_chirho: DigestChirho,
    },
    JournalChirho(JournalErrorChirho),
}

impl std::fmt::Display for EffectCompensationJournalErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IntentConflictChirho {
                key_chirho,
                existing_intent_ref_chirho,
                attempted_intent_ref_chirho,
            } => write!(
                formatter_chirho,
                "compensation intent conflict at {key_chirho}: existing {} attempted {}",
                existing_intent_ref_chirho.0, attempted_intent_ref_chirho.0
            ),
            Self::JournalChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "compensation journal refused: {error_chirho:?}"
                )
            }
        }
    }
}

impl std::error::Error for EffectCompensationJournalErrorChirho {}

impl From<JournalErrorChirho> for EffectCompensationJournalErrorChirho {
    fn from(error_chirho: JournalErrorChirho) -> Self {
        Self::JournalChirho(error_chirho)
    }
}

impl<'ports_chirho> LedgerJournalChirho<'ports_chirho> {
    /// Verify one canonical signed intent and append its escrow Hold through the SAME admission
    /// and storage path as every other record. Every authority-bearing request coordinate is
    /// derived from the verified intent; the caller supplies only bytes plus the injected root.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf3-effect-commit-second-seat-chirho.md`.
    pub fn append_effect_intent_chirho(
        &mut self,
        intent_line_chirho: &str,
        verifier_chirho: &dyn EffectIntentSignerPortChirho,
    ) -> Result<AppendReceiptChirho, JournalErrorChirho> {
        let verified_chirho = verify_effect_intent_line_chirho(intent_line_chirho, verifier_chirho)
            .map_err(|error_chirho| JournalErrorChirho::EffectIntentChirho {
                detail_chirho: error_chirho.to_string(),
            })?;
        let key_chirho = verified_chirho.key_chirho().to_owned();
        let intent_ref_chirho =
            parse_effect_intent_key_chirho(&key_chirho).map_err(|error_chirho| {
                JournalErrorChirho::EffectIntentChirho {
                    detail_chirho: error_chirho.to_string(),
                }
            })?;
        let intent_chirho = verified_chirho.into_intent_chirho();
        if intent_chirho.original_effect_key_chirho.is_some() {
            return Err(JournalErrorChirho::EffectIntentChirho {
                detail_chirho: "compensation intent cannot enter the forward effect-intent door"
                    .to_owned(),
            });
        }

        self.prune_effect_receipt_window_chirho();
        // An in-window same-K retry returns the ORIGINAL durable receipt before cut/fold. The
        // receipt is reconstructed solely from journal-derived coordinates, so retry adds no write.
        if let Some(entry_chirho) = self.effect_receipt_window_chirho.get(&key_chirho) {
            if entry_chirho.intent_ref_chirho != intent_ref_chirho {
                return Err(JournalErrorChirho::ChainChirho {
                    detail_chirho: "effect receipt key/ref binding diverged".to_owned(),
                });
            }
            return Ok(Self::hold_receipt_from_window_entry_chirho(entry_chirho));
        }
        self.append_new_effect_hold_chirho(
            intent_chirho,
            intent_ref_chirho.clone(),
            key_chirho,
            intent_ref_chirho,
        )
    }

    /// Dedicated compensation door. The opaque authorization token binds the exact signed intent,
    /// deterministic one-per-original K, lineage depth, and breaker decision before this method can
    /// append a Hold. The ordinary intent door refuses the same bytes.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf3-effect-commit-second-seat-chirho.md`.
    pub fn append_effect_compensation_chirho(
        &mut self,
        intent_line_chirho: &str,
        verifier_chirho: &dyn EffectIntentSignerPortChirho,
        authorization_chirho: &VerifiedEffectCompensationChirho,
    ) -> Result<AppendReceiptChirho, EffectCompensationJournalErrorChirho> {
        let verified_chirho = verify_effect_intent_line_chirho(intent_line_chirho, verifier_chirho)
            .map_err(|error_chirho| JournalErrorChirho::EffectIntentChirho {
                detail_chirho: error_chirho.to_string(),
            })?;
        let intent_ref_chirho = verified_chirho
            .key_chirho()
            .strip_prefix(EFFECT_INTENT_KEY_PREFIX_CHIRHO)
            .map(|digest_chirho| DigestChirho(digest_chirho.to_owned()))
            .ok_or_else(|| JournalErrorChirho::EffectIntentChirho {
                detail_chirho: "verified compensation intent has no content ref".to_owned(),
            })?;
        let intent_chirho = verified_chirho.into_intent_chirho();
        let original_effect_key_chirho = intent_chirho
            .original_effect_key_chirho
            .as_ref()
            .ok_or_else(|| JournalErrorChirho::EffectIntentChirho {
                detail_chirho: "compensation door requires original_effect_key_chirho".to_owned(),
            })?;
        let compensation_key_chirho = effect_compensation_key_chirho(original_effect_key_chirho)
            .map_err(|error_chirho| JournalErrorChirho::EffectIntentChirho {
                detail_chirho: error_chirho.to_string(),
            })?;
        let control_saga_id_chirho = parse_effect_compensation_key_chirho(&compensation_key_chirho)
            .map_err(|error_chirho| JournalErrorChirho::EffectIntentChirho {
                detail_chirho: error_chirho.to_string(),
            })?;
        if authorization_chirho.intent_ref_chirho() != &intent_ref_chirho
            || authorization_chirho.compensation_key_chirho() != compensation_key_chirho
            || authorization_chirho.control_saga_id_chirho() != &control_saga_id_chirho
            || authorization_chirho.original_effect_key_chirho() != original_effect_key_chirho
        {
            return Err(JournalErrorChirho::EffectIntentChirho {
                detail_chirho: "compensation authorization token does not bind this signed intent"
                    .to_owned(),
            }
            .into());
        }

        self.prune_effect_receipt_window_chirho();
        if let Some(entry_chirho) = self
            .effect_receipt_window_chirho
            .get(&compensation_key_chirho)
        {
            if entry_chirho.intent_ref_chirho != intent_ref_chirho {
                return Err(EffectCompensationJournalErrorChirho::IntentConflictChirho {
                    key_chirho: compensation_key_chirho,
                    existing_intent_ref_chirho: entry_chirho.intent_ref_chirho.clone(),
                    attempted_intent_ref_chirho: intent_ref_chirho,
                });
            }
            return Ok(Self::hold_receipt_from_window_entry_chirho(entry_chirho));
        }
        self.append_new_effect_hold_chirho(
            intent_chirho,
            intent_ref_chirho,
            compensation_key_chirho,
            control_saga_id_chirho,
        )
        .map_err(Into::into)
    }

    fn append_new_effect_hold_chirho(
        &mut self,
        intent_chirho: EffectIntentChirho,
        intent_ref_chirho: DigestChirho,
        key_chirho: String,
        control_saga_id_chirho: DigestChirho,
    ) -> Result<AppendReceiptChirho, JournalErrorChirho> {
        // A reserved key in the legacy set can only come from pre-window state that escaped the
        // sidecar migration fallback. Refuse rather than re-apply without an original receipt.
        if self.idempotency_keys_chirho.contains(&key_chirho) {
            return Err(JournalErrorChirho::EffectIntentChirho {
                detail_chirho: "reserved intent key lacks rebuildable receipt coordinates"
                    .to_owned(),
            });
        }
        let idempotency_horizon_ms_chirho = match self
            .kind_registry_chirho
            .resolve_recorded_ref_retention_window_chirho(
                &intent_chirho.resolved_price_chirho.kind_policy_ref_chirho,
            ) {
            RecordedRetentionWindowChirho::BoundedChirho(window_chirho) => {
                window_chirho.idempotency_horizon_ms_chirho
            }
            RecordedRetentionWindowChirho::RetainIndefinitelyChirho => {
                return Err(JournalErrorChirho::EffectIntentChirho {
                    detail_chirho:
                        "CF3 effect intent requires a registry-bounded idempotency window"
                            .to_owned(),
                })
            }
        };
        let intent_age_ms_chirho = self.tail_hlc_chirho.physical_ms_chirho.saturating_sub(
            intent_chirho
                .journal_cut_chirho
                .tail_hlc_chirho
                .physical_ms_chirho,
        );
        if intent_age_ms_chirho > idempotency_horizon_ms_chirho {
            return Err(JournalErrorChirho::StaleIntentChirho {
                key_chirho,
                age_ms_chirho: intent_age_ms_chirho,
                idempotency_horizon_ms_chirho,
            });
        }
        if intent_chirho.journal_cut_chirho != self.effect_intent_cut_chirho() {
            return Err(JournalErrorChirho::EffectIntentChirho {
                detail_chirho:
                    "signed effect intent cut does not equal this journal's verified current cut"
                        .to_owned(),
            });
        }

        let request_chirho = AppendRequestChirho {
            op_chirho: LedgerOpChirho::EscrowHoldChirho {
                control_chirho: EscrowControlChirho {
                    saga_id_chirho: control_saga_id_chirho,
                    step_chirho: intent_chirho.effect_step_chirho,
                },
            },
            legs_chirho: vec![AppendLegRequestChirho {
                account_chirho: intent_chirho.payer_account_chirho,
                kind_policy_ref_chirho: intent_chirho.resolved_price_chirho.kind_policy_ref_chirho,
                delta_chirho: LegDeltaChirho::HoldChirho,
                amount_chirho: intent_chirho.resolved_price_chirho.amount_chirho,
                counterpart_chirho: None,
            }],
            idempotency_key_chirho: key_chirho,
            provenance_chirho: Some(intent_ref_chirho.clone()),
            attribution_chirho: intent_chirho.attribution_chirho,
        };
        self.append_request_chirho(
            request_chirho,
            AppendIdempotencyClassChirho::VerifiedEffectIntentChirho { intent_ref_chirho },
        )
    }

    /// Verify the original intent and its one signed terminal outcome, derive every terminal leg
    /// under the CURRENT stable-kind policy, then invoke the SAME full admission/storage path.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf3-effect-commit-second-seat-chirho.md`.
    pub fn append_effect_terminal_chirho(
        &mut self,
        intent_line_chirho: &str,
        intent_verifier_chirho: &dyn EffectIntentSignerPortChirho,
        terminal_line_chirho: &str,
        terminal_verifier_chirho: &dyn EffectTerminalSignerPortChirho,
    ) -> Result<AppendReceiptChirho, JournalErrorChirho> {
        let verified_intent_chirho =
            verify_effect_intent_line_chirho(intent_line_chirho, intent_verifier_chirho).map_err(
                |error_chirho| JournalErrorChirho::EffectTerminalChirho {
                    detail_chirho: format!("original intent does not verify: {error_chirho}"),
                },
            )?;
        let intent_key_chirho = verified_intent_chirho.key_chirho().to_owned();
        let intent_ref_chirho =
            parse_effect_intent_key_chirho(&intent_key_chirho).map_err(|error_chirho| {
                JournalErrorChirho::EffectTerminalChirho {
                    detail_chirho: error_chirho.to_string(),
                }
            })?;
        let intent_chirho = verified_intent_chirho.into_intent_chirho();
        let (receipt_key_chirho, control_saga_id_chirho) = if let Some(original_effect_key_chirho) =
            intent_chirho.original_effect_key_chirho.as_deref()
        {
            let key_chirho = effect_compensation_key_chirho(original_effect_key_chirho).map_err(
                |error_chirho| JournalErrorChirho::EffectTerminalChirho {
                    detail_chirho: error_chirho.to_string(),
                },
            )?;
            let control_chirho =
                parse_effect_compensation_key_chirho(&key_chirho).map_err(|error_chirho| {
                    JournalErrorChirho::EffectTerminalChirho {
                        detail_chirho: error_chirho.to_string(),
                    }
                })?;
            (key_chirho, control_chirho)
        } else {
            (intent_key_chirho.clone(), intent_ref_chirho.clone())
        };
        let verified_terminal_chirho = verify_effect_terminal_outcome_line_chirho(
            terminal_line_chirho,
            terminal_verifier_chirho,
        )
        .map_err(|error_chirho| JournalErrorChirho::EffectTerminalChirho {
            detail_chirho: error_chirho.to_string(),
        })?;
        if verified_terminal_chirho.outcome_chirho().intent_ref_chirho != intent_ref_chirho {
            return Err(JournalErrorChirho::EffectTerminalChirho {
                detail_chirho: "terminal outcome does not bind the verified original intent"
                    .to_owned(),
            });
        }
        let terminal_key_chirho = verified_terminal_chirho.terminal_key_chirho().to_owned();
        let outcome_ref_chirho = verified_terminal_chirho.outcome_ref_chirho().clone();
        let disposition_chirho = verified_terminal_chirho
            .outcome_chirho()
            .disposition_chirho
            .clone();

        self.prune_effect_receipt_window_chirho();
        let entry_chirho = self
            .effect_receipt_window_chirho
            .get(&receipt_key_chirho)
            .ok_or_else(|| JournalErrorChirho::EffectTerminalChirho {
                detail_chirho: "terminal outcome has no retained original intent receipt"
                    .to_owned(),
            })?;
        if entry_chirho.intent_ref_chirho != intent_ref_chirho {
            return Err(JournalErrorChirho::ChainChirho {
                detail_chirho: "terminal receipt key/ref binding diverged".to_owned(),
            });
        }
        if let Some(existing_outcome_ref_chirho) = &entry_chirho.terminal_outcome_ref_chirho {
            if existing_outcome_ref_chirho == &outcome_ref_chirho {
                return Self::terminal_receipt_from_window_entry_chirho(entry_chirho).ok_or_else(
                    || JournalErrorChirho::ChainChirho {
                        detail_chirho:
                            "terminal outcome exists without retained terminal coordinates"
                                .to_owned(),
                    },
                );
            }
            return Err(JournalErrorChirho::EffectTerminalConflictChirho {
                key_chirho: terminal_key_chirho,
                existing_outcome_ref_chirho: existing_outcome_ref_chirho.clone(),
                attempted_outcome_ref_chirho: outcome_ref_chirho,
            });
        }

        let hold_key_chirho = EscrowHoldKeyChirho {
            account_chirho: intent_chirho.payer_account_chirho.clone(),
            saga_id_chirho: control_saga_id_chirho.clone(),
            step_chirho: intent_chirho.effect_step_chirho,
        };
        if !self.active_holds_chirho.contains_key(&hold_key_chirho) {
            return Err(JournalErrorChirho::EffectTerminalChirho {
                detail_chirho: "terminal outcome has no matching live Hold".to_owned(),
            });
        }

        let continuation_chirho = self
            .kind_registry_chirho
            .resolve_current_continuation_by_kind_chirho(
                &intent_chirho.resolved_price_chirho.kind_id_chirho,
            )
            .ok_or_else(|| JournalErrorChirho::EffectTerminalChirho {
                detail_chirho: "current stable-kind continuation policy is unavailable".to_owned(),
            })?;
        if continuation_chirho.policy_chirho.kind_id_chirho
            != intent_chirho.resolved_price_chirho.kind_id_chirho
        {
            return Err(JournalErrorChirho::EffectTerminalChirho {
                detail_chirho: "current continuation returned a different stable kind".to_owned(),
            });
        }
        let window_chirho = continuation_chirho
            .policy_chirho
            .idempotency_window_chirho
            .ok_or_else(|| JournalErrorChirho::EffectTerminalChirho {
                detail_chirho: "current continuation policy has no CF3 retry/finality window"
                    .to_owned(),
            })?;
        // Terminal finality starts when the Hold was durably admitted. The pre-Hold cut may be
        // old simply because the journal was idle, which must not strand a committed provider.
        let terminal_age_ms_chirho = self
            .tail_hlc_chirho
            .physical_ms_chirho
            .saturating_sub(entry_chirho.committed_hlc_chirho.physical_ms_chirho);
        if terminal_age_ms_chirho > window_chirho.retry_finality_horizon_ms_chirho {
            return Err(JournalErrorChirho::StaleEffectTerminalChirho {
                intent_ref_chirho,
                age_ms_chirho: terminal_age_ms_chirho,
                retry_finality_horizon_ms_chirho: window_chirho.retry_finality_horizon_ms_chirho,
            });
        }

        let control_chirho = EscrowControlChirho {
            saga_id_chirho: control_saga_id_chirho,
            step_chirho: intent_chirho.effect_step_chirho,
        };
        let (op_chirho, legs_chirho) = match disposition_chirho {
            EffectTerminalDispositionChirho::CommittedChirho { .. } => {
                let settlement_owner_chirho = continuation_chirho
                    .policy_chirho
                    .settlement_owner_chirho
                    .ok_or_else(|| JournalErrorChirho::EffectTerminalChirho {
                        detail_chirho: "current billing-kind policy has no settlement owner"
                            .to_owned(),
                    })?;
                (
                    LedgerOpChirho::EscrowFinalizeChirho { control_chirho },
                    vec![
                        AppendLegRequestChirho {
                            account_chirho: intent_chirho.payer_account_chirho.clone(),
                            kind_policy_ref_chirho: continuation_chirho
                                .kind_policy_ref_chirho
                                .clone(),
                            delta_chirho: LegDeltaChirho::FinalizeChirho,
                            amount_chirho: intent_chirho.resolved_price_chirho.amount_chirho,
                            counterpart_chirho: None,
                        },
                        AppendLegRequestChirho {
                            account_chirho: AccountIdChirho::new_chirho(
                                settlement_owner_chirho,
                                intent_chirho.resolved_price_chirho.kind_id_chirho.clone(),
                            ),
                            kind_policy_ref_chirho: continuation_chirho.kind_policy_ref_chirho,
                            delta_chirho: LegDeltaChirho::CreditChirho,
                            amount_chirho: intent_chirho.resolved_price_chirho.amount_chirho,
                            counterpart_chirho: None,
                        },
                    ],
                )
            }
            EffectTerminalDispositionChirho::DefiniteNoEffectChirho => (
                LedgerOpChirho::EscrowReleaseChirho { control_chirho },
                vec![AppendLegRequestChirho {
                    account_chirho: intent_chirho.payer_account_chirho.clone(),
                    kind_policy_ref_chirho: continuation_chirho.kind_policy_ref_chirho,
                    delta_chirho: LegDeltaChirho::ReleaseChirho,
                    amount_chirho: intent_chirho.resolved_price_chirho.amount_chirho,
                    counterpart_chirho: None,
                }],
            ),
        };
        self.append_request_chirho(
            AppendRequestChirho {
                op_chirho,
                legs_chirho,
                idempotency_key_chirho: terminal_key_chirho,
                provenance_chirho: Some(outcome_ref_chirho.clone()),
                attribution_chirho: intent_chirho.attribution_chirho,
            },
            AppendIdempotencyClassChirho::VerifiedEffectTerminalChirho {
                intent_ref_chirho,
                outcome_ref_chirho,
            },
        )
    }

    /// The fsck inventory: only receipt-backed CF3 Holds, never unrelated CF2 saga Holds.
    pub fn active_effect_intent_refs_chirho(&self) -> Vec<DigestChirho> {
        let active_control_refs_chirho = self
            .active_holds_chirho
            .keys()
            .map(|key_chirho| key_chirho.saga_id_chirho.clone())
            .collect::<BTreeSet<_>>();
        self.effect_receipt_window_chirho
            .values()
            .filter(|entry_chirho| {
                entry_chirho.terminal_outcome_ref_chirho.is_none()
                    && active_control_refs_chirho
                        .contains(entry_chirho.effective_control_saga_id_chirho())
            })
            .map(|entry_chirho| entry_chirho.intent_ref_chirho.clone())
            .collect()
    }

    /// Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.
    pub fn verified_effect_receipt_inventory_chirho(
        &self,
    ) -> Vec<VerifiedEffectReceiptInventoryEntryChirho> {
        self.effect_receipt_window_chirho
            .values()
            .map(|entry_chirho| {
                let hold_receipt_chirho = Self::hold_receipt_from_window_entry_chirho(entry_chirho);
                let terminal_receipt_chirho =
                    Self::terminal_receipt_from_window_entry_chirho(entry_chirho);
                VerifiedEffectReceiptInventoryEntryChirho {
                    intent_ref_chirho: entry_chirho.intent_ref_chirho.clone(),
                    control_saga_id_chirho: entry_chirho.control_saga_id_chirho.clone(),
                    hold_receipt_chirho: EffectCommitJournalReceiptChirho {
                        seq_chirho: hold_receipt_chirho.seq_chirho,
                        record_digest_chirho: hold_receipt_chirho.record_digest_chirho,
                        hlc_chirho: hold_receipt_chirho.hlc_chirho,
                    },
                    terminal_outcome_ref_chirho: entry_chirho.terminal_outcome_ref_chirho.clone(),
                    terminal_receipt_chirho: terminal_receipt_chirho.map(|receipt_chirho| {
                        EffectCommitJournalReceiptChirho {
                            seq_chirho: receipt_chirho.seq_chirho,
                            record_digest_chirho: receipt_chirho.record_digest_chirho,
                            hlc_chirho: receipt_chirho.hlc_chirho,
                        }
                    }),
                }
            })
            .collect()
    }

    pub fn effect_intent_journal_state_chirho(
        &self,
        intent_ref_chirho: &DigestChirho,
    ) -> Option<EffectIntentJournalStateChirho> {
        let (_, entry_chirho) =
            self.effect_receipt_entry_by_intent_ref_chirho(intent_ref_chirho)?;
        let latest_receipt_chirho = Self::terminal_receipt_from_window_entry_chirho(entry_chirho)
            .unwrap_or_else(|| Self::hold_receipt_from_window_entry_chirho(entry_chirho));
        Some(EffectIntentJournalStateChirho {
            intent_ref_chirho: entry_chirho.intent_ref_chirho.clone(),
            receipt_chirho: EffectCommitJournalReceiptChirho {
                seq_chirho: latest_receipt_chirho.seq_chirho,
                record_digest_chirho: latest_receipt_chirho.record_digest_chirho,
                hlc_chirho: latest_receipt_chirho.hlc_chirho,
            },
            terminal_outcome_ref_chirho: entry_chirho.terminal_outcome_ref_chirho.clone(),
        })
    }

    pub(crate) fn append_idempotency_duplicate_chirho(
        &self,
        class_chirho: &AppendIdempotencyClassChirho,
        key_chirho: &str,
    ) -> Result<bool, JournalErrorChirho> {
        match class_chirho {
            AppendIdempotencyClassChirho::LegacyUnprunedChirho => {
                Ok(self.idempotency_keys_chirho.contains(key_chirho))
            }
            AppendIdempotencyClassChirho::VerifiedEffectIntentChirho { .. } => {
                Ok(self.effect_receipt_window_chirho.contains_key(key_chirho))
            }
            AppendIdempotencyClassChirho::VerifiedEffectTerminalChirho {
                intent_ref_chirho,
                outcome_ref_chirho,
            } => {
                let (_, entry_chirho) = self
                    .effect_receipt_entry_by_intent_ref_chirho(intent_ref_chirho)
                    .ok_or_else(|| JournalErrorChirho::EffectTerminalChirho {
                        detail_chirho: "terminal append has no original intent receipt".to_owned(),
                    })?;
                // Defense in depth behind the dedicated door's primary conflict check. If a
                // second internal terminal-class caller is added, pin this branch independently.
                match &entry_chirho.terminal_outcome_ref_chirho {
                    None => Ok(false),
                    Some(existing_chirho) if existing_chirho == outcome_ref_chirho => Ok(true),
                    Some(existing_chirho) => {
                        Err(JournalErrorChirho::EffectTerminalConflictChirho {
                            key_chirho: key_chirho.to_owned(),
                            existing_outcome_ref_chirho: existing_chirho.clone(),
                            attempted_outcome_ref_chirho: outcome_ref_chirho.clone(),
                        })
                    }
                }
            }
        }
    }

    fn effect_receipt_entry_by_intent_ref_chirho(
        &self,
        intent_ref_chirho: &DigestChirho,
    ) -> Option<(&String, &EffectReceiptWindowEntryChirho)> {
        let ordinary_key_chirho = intent_key_from_ref_chirho(intent_ref_chirho);
        if let Some(entry_chirho) = self.effect_receipt_window_chirho.get(&ordinary_key_chirho) {
            if entry_chirho.intent_ref_chirho == *intent_ref_chirho {
                return self
                    .effect_receipt_window_chirho
                    .get_key_value(&ordinary_key_chirho);
            }
        }
        self.effect_receipt_window_chirho
            .iter()
            .find(|(_, entry_chirho)| entry_chirho.intent_ref_chirho == *intent_ref_chirho)
    }

    fn terminal_receipt_key_chirho(
        &self,
        intent_ref_chirho: &DigestChirho,
        control_saga_id_chirho: &DigestChirho,
    ) -> Result<String, JournalErrorChirho> {
        let candidate_keys_chirho = [
            intent_key_from_ref_chirho(intent_ref_chirho),
            compensation_key_from_control_chirho(control_saga_id_chirho),
        ];
        let mut matched_key_chirho = None;
        for candidate_key_chirho in candidate_keys_chirho {
            let Some(entry_chirho) = self.effect_receipt_window_chirho.get(&candidate_key_chirho)
            else {
                continue;
            };
            if entry_chirho.intent_ref_chirho != *intent_ref_chirho
                || entry_chirho.effective_control_saga_id_chirho() != control_saga_id_chirho
            {
                continue;
            }
            if matched_key_chirho.is_some() {
                return Err(JournalErrorChirho::ChainChirho {
                    detail_chirho:
                        "terminal coordinates ambiguously match two retained intent receipts"
                            .to_owned(),
                });
            }
            matched_key_chirho = Some(candidate_key_chirho);
        }
        matched_key_chirho.ok_or_else(|| JournalErrorChirho::ChainChirho {
            detail_chirho: "terminal coordinates have no matching retained intent receipt"
                .to_owned(),
        })
    }

    pub(crate) fn effect_receipt_transition_for_append_chirho(
        &self,
        record_chirho: &LedgerRecordChirho,
        class_chirho: AppendIdempotencyClassChirho,
        policy_refs_chirho: Vec<AssetKindRefChirho>,
    ) -> Result<EffectReceiptTransitionChirho, JournalErrorChirho> {
        let transition_chirho = match class_chirho {
            AppendIdempotencyClassChirho::LegacyUnprunedChirho => {
                EffectReceiptTransitionChirho::LegacyUnprunedChirho
            }
            AppendIdempotencyClassChirho::VerifiedEffectIntentChirho { intent_ref_chirho } => {
                let control_saga_id_chirho =
                    record_escrow_control_saga_id_chirho(record_chirho)?.clone();
                EffectReceiptTransitionChirho::IntentChirho {
                    intent_ref_chirho,
                    control_saga_id_chirho,
                    policy_refs_chirho,
                }
            }
            AppendIdempotencyClassChirho::VerifiedEffectTerminalChirho {
                intent_ref_chirho,
                outcome_ref_chirho,
            } => {
                let control_saga_id_chirho =
                    record_escrow_control_saga_id_chirho(record_chirho)?.clone();
                let receipt_key_chirho =
                    self.terminal_receipt_key_chirho(&intent_ref_chirho, &control_saga_id_chirho)?;
                EffectReceiptTransitionChirho::TerminalChirho {
                    receipt_key_chirho,
                    intent_ref_chirho,
                    control_saga_id_chirho,
                    outcome_ref_chirho,
                    policy_refs_chirho,
                }
            }
        };
        validate_transition_record_binding_chirho(record_chirho, &transition_chirho)?;
        Ok(transition_chirho)
    }

    pub(crate) fn effect_receipt_transition_for_replay_chirho(
        &self,
        record_chirho: &LedgerRecordChirho,
    ) -> Result<EffectReceiptTransitionChirho, JournalErrorChirho> {
        let policy_refs_chirho = record_chirho
            .legs_chirho
            .iter()
            .map(|leg_chirho| leg_chirho.kind_policy_ref_chirho.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let record_fact_chirho = classify_effect_record_fact_chirho(record_chirho)
            .map_err(effect_record_fact_refusal_to_journal_error_chirho)?;
        let transition_chirho = match record_fact_chirho {
            EffectRecordFactChirho::LedgerOnlyChirho => {
                EffectReceiptTransitionChirho::LegacyUnprunedChirho
            }
            EffectRecordFactChirho::EffectHoldChirho {
                intent_ref_chirho,
                control_chirho,
                ..
            } => EffectReceiptTransitionChirho::IntentChirho {
                intent_ref_chirho,
                control_saga_id_chirho: control_chirho.saga_id_chirho,
                policy_refs_chirho,
            },
            EffectRecordFactChirho::EffectTerminalChirho {
                intent_ref_chirho,
                outcome_ref_chirho,
                control_chirho,
                ..
            } => {
                let receipt_key_chirho = self.terminal_receipt_key_chirho(
                    &intent_ref_chirho,
                    &control_chirho.saga_id_chirho,
                )?;
                EffectReceiptTransitionChirho::TerminalChirho {
                    receipt_key_chirho,
                    intent_ref_chirho,
                    control_saga_id_chirho: control_chirho.saga_id_chirho,
                    outcome_ref_chirho,
                    policy_refs_chirho,
                }
            }
        };
        self.preview_replay_effect_receipt_transition_chirho(record_chirho, &transition_chirho)?;
        Ok(transition_chirho)
    }

    fn preview_replay_effect_receipt_transition_chirho(
        &self,
        record_chirho: &LedgerRecordChirho,
        transition_chirho: &EffectReceiptTransitionChirho,
    ) -> Result<(), JournalErrorChirho> {
        match transition_chirho {
            EffectReceiptTransitionChirho::LegacyUnprunedChirho => {
                if self
                    .idempotency_keys_chirho
                    .contains(&record_chirho.idempotency_key_chirho)
                {
                    return Err(JournalErrorChirho::ChainChirho {
                        detail_chirho: format!(
                            "duplicate legacy idempotency key at seq {}",
                            record_chirho.seq_chirho
                        ),
                    });
                }
            }
            EffectReceiptTransitionChirho::IntentChirho { .. } => {
                if self
                    .effect_receipt_window_chirho
                    .contains_key(&record_chirho.idempotency_key_chirho)
                {
                    return Err(JournalErrorChirho::ChainChirho {
                        detail_chirho: format!(
                            "duplicate reserved CF3 intent key at seq {}",
                            record_chirho.seq_chirho
                        ),
                    });
                }
            }
            EffectReceiptTransitionChirho::TerminalChirho {
                receipt_key_chirho,
                intent_ref_chirho,
                outcome_ref_chirho,
                ..
            } => {
                let entry_chirho = self
                    .effect_receipt_window_chirho
                    .get(receipt_key_chirho)
                    .ok_or_else(|| JournalErrorChirho::ChainChirho {
                        detail_chirho: format!(
                            "reserved CF3 terminal at seq {} has no prior intent",
                            record_chirho.seq_chirho
                        ),
                    })?;
                if entry_chirho.intent_ref_chirho != *intent_ref_chirho {
                    return Err(JournalErrorChirho::ChainChirho {
                        detail_chirho: "terminal receipt key/ref binding diverged".to_owned(),
                    });
                }
                if let Some(existing_outcome_ref_chirho) = &entry_chirho.terminal_outcome_ref_chirho
                {
                    if existing_outcome_ref_chirho != outcome_ref_chirho {
                        return Err(JournalErrorChirho::EffectTerminalConflictChirho {
                            key_chirho: record_chirho.idempotency_key_chirho.clone(),
                            existing_outcome_ref_chirho: existing_outcome_ref_chirho.clone(),
                            attempted_outcome_ref_chirho: outcome_ref_chirho.clone(),
                        });
                    }
                    return Err(JournalErrorChirho::ChainChirho {
                        detail_chirho: format!(
                            "duplicate reserved CF3 terminal key at seq {}",
                            record_chirho.seq_chirho
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    /// The ONE receipt mutation used by live append and verified replay.
    pub(crate) fn apply_effect_receipt_transition_chirho(
        &mut self,
        record_chirho: &LedgerRecordChirho,
        line_digest_chirho: &DigestChirho,
        transition_chirho: EffectReceiptTransitionChirho,
    ) -> Result<(), JournalErrorChirho> {
        match transition_chirho {
            EffectReceiptTransitionChirho::LegacyUnprunedChirho => {
                self.idempotency_keys_chirho
                    .insert(record_chirho.idempotency_key_chirho.clone());
            }
            EffectReceiptTransitionChirho::IntentChirho {
                intent_ref_chirho,
                control_saga_id_chirho,
                policy_refs_chirho,
            } => {
                let stored_control_saga_id_chirho =
                    (control_saga_id_chirho != intent_ref_chirho).then_some(control_saga_id_chirho);
                self.effect_receipt_window_chirho.insert(
                    record_chirho.idempotency_key_chirho.clone(),
                    EffectReceiptWindowEntryChirho {
                        intent_ref_chirho,
                        control_saga_id_chirho: stored_control_saga_id_chirho,
                        terminal_outcome_ref_chirho: None,
                        terminal_receipt_chirho: None,
                        committed_seq_chirho: record_chirho.seq_chirho,
                        committed_hlc_chirho: record_chirho.hlc_chirho.clone(),
                        stored_record_digest_chirho: line_digest_chirho.clone(),
                        policy_refs_chirho,
                    },
                );
            }
            EffectReceiptTransitionChirho::TerminalChirho {
                receipt_key_chirho,
                intent_ref_chirho,
                control_saga_id_chirho,
                outcome_ref_chirho,
                policy_refs_chirho,
            } => {
                let entry_chirho = self
                    .effect_receipt_window_chirho
                    .get_mut(&receipt_key_chirho)
                    .ok_or_else(|| JournalErrorChirho::ChainChirho {
                        detail_chirho: "terminal transition has no original intent receipt"
                            .to_owned(),
                    })?;
                if entry_chirho.intent_ref_chirho != intent_ref_chirho {
                    return Err(JournalErrorChirho::ChainChirho {
                        detail_chirho: "terminal transition intent binding diverged".to_owned(),
                    });
                }
                if entry_chirho.effective_control_saga_id_chirho() != &control_saga_id_chirho {
                    return Err(JournalErrorChirho::ChainChirho {
                        detail_chirho: "terminal transition control binding diverged".to_owned(),
                    });
                }
                if let Some(existing_outcome_ref_chirho) = &entry_chirho.terminal_outcome_ref_chirho
                {
                    if existing_outcome_ref_chirho != &outcome_ref_chirho {
                        return Err(JournalErrorChirho::EffectTerminalConflictChirho {
                            key_chirho: record_chirho.idempotency_key_chirho.clone(),
                            existing_outcome_ref_chirho: existing_outcome_ref_chirho.clone(),
                            attempted_outcome_ref_chirho: outcome_ref_chirho,
                        });
                    }
                    return Err(JournalErrorChirho::ChainChirho {
                        detail_chirho: "duplicate terminal transition".to_owned(),
                    });
                }
                entry_chirho.terminal_outcome_ref_chirho = Some(outcome_ref_chirho);
                entry_chirho.terminal_receipt_chirho =
                    Some(EffectTerminalReceiptCoordinatesChirho {
                        seq_chirho: record_chirho.seq_chirho,
                        hlc_chirho: record_chirho.hlc_chirho.clone(),
                        stored_record_digest_chirho: line_digest_chirho.clone(),
                    });
                entry_chirho.policy_refs_chirho = policy_refs_chirho;
            }
        }
        Ok(())
    }
}

fn validate_transition_record_binding_chirho(
    record_chirho: &LedgerRecordChirho,
    transition_chirho: &EffectReceiptTransitionChirho,
) -> Result<(), JournalErrorChirho> {
    let record_fact_chirho = classify_effect_record_fact_chirho(record_chirho)
        .map_err(effect_record_fact_refusal_to_journal_error_chirho)?;
    let binding_matches_chirho = match (&record_fact_chirho, transition_chirho) {
        (
            EffectRecordFactChirho::LedgerOnlyChirho,
            EffectReceiptTransitionChirho::LegacyUnprunedChirho,
        ) => true,
        (
            EffectRecordFactChirho::EffectHoldChirho {
                intent_ref_chirho: fact_intent_ref_chirho,
                control_chirho,
                ..
            },
            EffectReceiptTransitionChirho::IntentChirho {
                intent_ref_chirho,
                control_saga_id_chirho,
                ..
            },
        ) => {
            fact_intent_ref_chirho == intent_ref_chirho
                && control_chirho.saga_id_chirho == *control_saga_id_chirho
        }
        (
            EffectRecordFactChirho::EffectTerminalChirho {
                intent_ref_chirho: fact_intent_ref_chirho,
                outcome_ref_chirho: fact_outcome_ref_chirho,
                control_chirho,
                ..
            },
            EffectReceiptTransitionChirho::TerminalChirho {
                receipt_key_chirho,
                intent_ref_chirho,
                control_saga_id_chirho,
                outcome_ref_chirho,
                ..
            },
        ) => {
            fact_intent_ref_chirho == intent_ref_chirho
                && fact_outcome_ref_chirho == outcome_ref_chirho
                && control_chirho.saga_id_chirho == *control_saga_id_chirho
                && receipt_key_binds_control_chirho(
                    receipt_key_chirho,
                    intent_ref_chirho,
                    control_saga_id_chirho,
                )
        }
        _ => false,
    };
    if binding_matches_chirho {
        Ok(())
    } else {
        Err(JournalErrorChirho::ChainChirho {
            detail_chirho: "reserved CF3 transition and record fact diverged".to_owned(),
        })
    }
}

fn effect_record_fact_refusal_to_journal_error_chirho(
    refusal_chirho: EffectRecordFactRefusalChirho,
) -> JournalErrorChirho {
    JournalErrorChirho::ChainChirho {
        detail_chirho: refusal_chirho.to_string(),
    }
}

fn record_escrow_control_saga_id_chirho(
    record_chirho: &LedgerRecordChirho,
) -> Result<&DigestChirho, JournalErrorChirho> {
    match &record_chirho.op_chirho {
        LedgerOpChirho::EscrowHoldChirho { control_chirho }
        | LedgerOpChirho::EscrowFinalizeChirho { control_chirho }
        | LedgerOpChirho::EscrowReleaseChirho { control_chirho } => {
            Ok(&control_chirho.saga_id_chirho)
        }
        _ => Err(JournalErrorChirho::ChainChirho {
            detail_chirho: "reserved CF3 receipt transition is not an escrow operation".to_owned(),
        }),
    }
}

fn receipt_key_binds_control_chirho(
    receipt_key_chirho: &str,
    intent_ref_chirho: &DigestChirho,
    control_saga_id_chirho: &DigestChirho,
) -> bool {
    (control_saga_id_chirho == intent_ref_chirho
        && receipt_key_chirho == intent_key_from_ref_chirho(intent_ref_chirho))
        || receipt_key_chirho == compensation_key_from_control_chirho(control_saga_id_chirho)
}

fn compensation_key_from_control_chirho(control_saga_id_chirho: &DigestChirho) -> String {
    format!(
        "{EFFECT_COMPENSATION_KEY_PREFIX_CHIRHO}{}",
        control_saga_id_chirho.0
    )
}

fn intent_key_from_ref_chirho(intent_ref_chirho: &DigestChirho) -> String {
    format!("{EFFECT_INTENT_KEY_PREFIX_CHIRHO}{}", intent_ref_chirho.0)
}
