// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! The one ledger-record append pipeline, including the optional production F1 mirror gate.
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/zone-mirror-before-ack-contract-chirho.md`.

use super::append_request_bounds_chirho::validate_append_request_bounds_chirho;
use super::epoch_first_record_tail_chirho::prepare_epoch_first_record_evidence_chirho;
use super::{
    storage_error_chirho, AppendIdempotencyClassChirho, AppendReceiptChirho, AppendRequestChirho,
    JournalErrorChirho, LedgerJournalChirho,
};
use crate::admission_chirho::{
    admit_chirho, fold_leg_post_chirho, AdmissionContextChirho, AdmissionRejectChirho,
    IdempotencyRetentionChirho,
};
use crate::append_mirror_chirho::{
    LedgerAppendMirrorCandidateChirho, LedgerAppendMirrorCandidateInputChirho,
    LedgerAppendMirrorTailChirho,
};
use cairn_effect_commit_chirho::intent_chirho::is_reserved_effect_intent_key_chirho;
use cairn_effect_commit_chirho::terminal_chirho::is_reserved_effect_terminal_key_chirho;
use cairn_ledger_model_chirho::ids_chirho::AccountIdChirho;
use cairn_ledger_model_chirho::record_chirho::{
    LedgerLegChirho, LedgerRecordChirho, LegPostStateChirho,
};
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_record_line_chirho, ledger_record_signed_content_line_chirho,
    stored_line_digest_chirho, LEDGER_RECORD_SCHEMA_V1_CHIRHO,
};
use std::collections::BTreeMap;

impl<'ports_chirho> LedgerJournalChirho<'ports_chirho> {
    pub fn append_chirho(
        &mut self,
        request_chirho: AppendRequestChirho,
    ) -> Result<AppendReceiptChirho, JournalErrorChirho> {
        if is_reserved_effect_intent_key_chirho(&request_chirho.idempotency_key_chirho) {
            return Err(JournalErrorChirho::EffectIntentChirho {
                detail_chirho: "reserved CF3 intent keys require the verified intent door"
                    .to_owned(),
            });
        }
        if is_reserved_effect_terminal_key_chirho(&request_chirho.idempotency_key_chirho) {
            return Err(JournalErrorChirho::EffectTerminalChirho {
                detail_chirho: "reserved CF3 terminal keys require the verified terminal door"
                    .to_owned(),
            });
        }
        self.append_request_chirho(
            request_chirho,
            AppendIdempotencyClassChirho::LegacyUnprunedChirho,
        )
    }

    pub(crate) fn append_request_chirho(
        &mut self,
        request_chirho: AppendRequestChirho,
        idempotency_class_chirho: AppendIdempotencyClassChirho,
    ) -> Result<AppendReceiptChirho, JournalErrorChirho> {
        // Engine-policy O(1)-bounded request fence: this MUST precede duplicate lookup, caller-field
        // cloning, BTreeMap folding, signing, and every storage operation. It deliberately does not
        // alter the frozen parser semantics of already-persisted ledger-record-v1 bytes.
        validate_append_request_bounds_chirho(&request_chirho)?;
        if let Some(append_mirror_chirho) = self.append_mirror_chirho.as_ref() {
            let local_tail_chirho = LedgerAppendMirrorTailChirho::new_chirho(
                self.cluster_id_chirho.clone(),
                self.genesis_digest_chirho.clone(),
                self.tail_seq_chirho,
                self.tail_digest_chirho.clone(),
                self.tail_hlc_chirho.clone(),
                self.last_recorded_epoch_chirho,
                self.current_epoch_chirho,
            );
            append_mirror_chirho
                .reconcile_before_append_chirho(&local_tail_chirho)
                .map_err(
                    |error_chirho| JournalErrorChirho::MirrorReconciliationRefusedChirho {
                        detail_chirho: error_chirho.to_string(),
                    },
                )?;
        }
        // Idempotency PRE-CHECK before the builder fold (#5028 hardening): a crash-retried request
        // whose original landed would otherwise hit the builder's fold against the ALREADY-APPLIED
        // state and refuse as Arithmetic/PostState - masking the honest signal. Surfacing the
        // typed duplicate FIRST makes every same-key retry self-announcing. Refusal-only reorder:
        // no record is ever admitted without the FULL admission gate below (B1 intact - admission
        // re-checks this same window at its own step).
        let duplicate_chirho = self.append_idempotency_duplicate_chirho(
            &idempotency_class_chirho,
            &request_chirho.idempotency_key_chirho,
        )?;
        if duplicate_chirho {
            return Err(JournalErrorChirho::AdmissionChirho {
                reject_chirho: AdmissionRejectChirho::IdempotencyDuplicateChirho,
            });
        }
        // Build legs: fold each requested leg's post from the live heads (same-account legs chain
        // within the record, mirroring the admission fence's own fold).
        let mut working_chirho: BTreeMap<AccountIdChirho, LegPostStateChirho> = BTreeMap::new();
        let mut legs_chirho: Vec<LedgerLegChirho> =
            Vec::with_capacity(request_chirho.legs_chirho.len());
        for request_leg_chirho in &request_chirho.legs_chirho {
            let state_chirho = working_chirho
                .entry(request_leg_chirho.account_chirho.clone())
                .or_insert_with(|| {
                    self.head_states_chirho
                        .get(&request_leg_chirho.account_chirho)
                        .cloned()
                        .unwrap_or(LegPostStateChirho {
                            credits_total_chirho: 0,
                            debits_total_chirho: 0,
                            held_chirho: 0,
                        })
                });
            fold_leg_post_chirho(
                state_chirho,
                &request_leg_chirho.delta_chirho,
                request_leg_chirho.amount_chirho,
            )?;
            legs_chirho.push(LedgerLegChirho {
                account_chirho: request_leg_chirho.account_chirho.clone(),
                kind_policy_ref_chirho: request_leg_chirho.kind_policy_ref_chirho.clone(),
                delta_chirho: request_leg_chirho.delta_chirho.clone(),
                amount_chirho: request_leg_chirho.amount_chirho,
                post_chirho: state_chirho.clone(),
                counterpart_chirho: request_leg_chirho.counterpart_chirho.clone(),
            });
        }
        // The first record under a freshly advanced lease carries the anchor binding the
        // pre-advance tail (chain continuity of the handoff; freshness is the lease grant's).
        let anchor_chirho =
            (self.current_epoch_chirho != self.last_recorded_epoch_chirho).then(|| {
                cairn_ledger_model_chirho::record_chirho::CrossZoneAnchorChirho {
                    inherited_epoch_chirho: self.last_recorded_epoch_chirho,
                    inherited_seq_chirho: self.tail_seq_chirho,
                    inherited_digest_chirho: self.tail_digest_chirho.clone(),
                }
            });
        let mut record_chirho = LedgerRecordChirho {
            schema_chirho: LEDGER_RECORD_SCHEMA_V1_CHIRHO.into(),
            format_version_chirho:
                cairn_ledger_model_chirho::wire_chirho::LEDGER_FORMAT_VERSION_V1_CHIRHO,
            seq_chirho: self.tail_seq_chirho + 1,
            prev_chirho: self.tail_digest_chirho.clone(),
            epoch_chirho: self.current_epoch_chirho,
            hlc_chirho: self.next_hlc_chirho(),
            legs_chirho,
            op_chirho: request_chirho.op_chirho,
            idempotency_key_chirho: request_chirho.idempotency_key_chirho,
            provenance_chirho: request_chirho.provenance_chirho,
            attribution_chirho: request_chirho.attribution_chirho,
            anchor_chirho: anchor_chirho.clone(),
            sig_chirho: String::new(),
            key_id_chirho: self.signer_chirho.key_id_chirho(),
        };
        let signed_content_chirho = ledger_record_signed_content_line_chirho(&record_chirho)?;
        record_chirho.sig_chirho = self
            .signer_chirho
            .sign_chirho(&signed_content_chirho)
            .map_err(|error_chirho| JournalErrorChirho::SignerChirho {
                detail_chirho: error_chirho.to_string(),
            })?;
        // FULL admission - the one gate; only its token's record reaches storage.
        let context_chirho = AdmissionContextChirho {
            expected_seq_chirho: self.tail_seq_chirho + 1,
            expected_prev_chirho: &self.tail_digest_chirho,
            current_epoch_chirho: self.current_epoch_chirho,
            tail_hlc_chirho: &self.tail_hlc_chirho,
            membership_chirho: self.membership_chirho,
            kind_registry_chirho: self.kind_registry_chirho,
            authority_chirho: self.authority_chirho,
            head_states_chirho: &self.head_states_chirho,
            supply_by_kind_chirho: &self.supply_by_kind_chirho,
            recent_idempotency_keys_chirho: &self.idempotency_keys_chirho,
            active_holds_chirho: &self.active_holds_chirho,
            cluster_chirho: &self.cluster_id_chirho,
            consumed_nullifiers_chirho: &self.consumed_nullifiers_chirho,
            finality_chirho: self.finality_chirho,
            expected_anchor_chirho: anchor_chirho.as_ref(),
        };
        let token_chirho = admit_chirho(&context_chirho, record_chirho)?;
        let (admitted_chirho, retention_chirho) = token_chirho.into_parts_chirho();
        let receipt_policy_refs_chirho = match &idempotency_class_chirho {
            AppendIdempotencyClassChirho::LegacyUnprunedChirho => Vec::new(),
            AppendIdempotencyClassChirho::VerifiedEffectIntentChirho { .. }
            | AppendIdempotencyClassChirho::VerifiedEffectTerminalChirho { .. } => {
                match retention_chirho {
                    IdempotencyRetentionChirho::BoundedChirho {
                        policy_refs_chirho, ..
                    } => policy_refs_chirho,
                    IdempotencyRetentionChirho::LegacyUnprunedChirho { .. } => {
                        let detail_chirho =
                            "CF3 effect admission resolved an unbounded policy".to_owned();
                        return Err(match idempotency_class_chirho {
                            AppendIdempotencyClassChirho::VerifiedEffectIntentChirho { .. } => {
                                JournalErrorChirho::EffectIntentChirho { detail_chirho }
                            }
                            AppendIdempotencyClassChirho::VerifiedEffectTerminalChirho {
                                ..
                            } => JournalErrorChirho::EffectTerminalChirho { detail_chirho },
                            AppendIdempotencyClassChirho::LegacyUnprunedChirho => unreachable!(),
                        });
                    }
                }
            }
        };
        let effect_receipt_transition_chirho = self.effect_receipt_transition_for_append_chirho(
            &admitted_chirho,
            idempotency_class_chirho,
            receipt_policy_refs_chirho,
        )?;
        let line_chirho = canonical_ledger_record_line_chirho(&admitted_chirho)?;
        let stored_record_digest_chirho = stored_line_digest_chirho(&line_chirho);
        let epoch_first_record_chirho = prepare_epoch_first_record_evidence_chirho(
            &admitted_chirho,
            &line_chirho,
            &stored_record_digest_chirho,
        )?;
        let mirror_candidate_chirho = self.append_mirror_chirho.as_ref().map(|_| {
            LedgerAppendMirrorCandidateChirho::new_chirho(LedgerAppendMirrorCandidateInputChirho {
                cluster_id_chirho: self.cluster_id_chirho.clone(),
                journal_genesis_digest_chirho: self.genesis_digest_chirho.clone(),
                predecessor_seq_chirho: self.tail_seq_chirho,
                predecessor_digest_chirho: self.tail_digest_chirho.clone(),
                record_seq_chirho: admitted_chirho.seq_chirho,
                record_digest_chirho: stored_record_digest_chirho.clone(),
                record_epoch_chirho: admitted_chirho.epoch_chirho,
                record_hlc_chirho: admitted_chirho.hlc_chirho.clone(),
                caller_idempotency_key_chirho: admitted_chirho.idempotency_key_chirho.clone(),
                canonical_record_line_chirho: line_chirho.clone(),
            })
        });
        if let (Some(append_mirror_chirho), Some(mirror_candidate_chirho)) = (
            self.append_mirror_chirho.as_ref(),
            mirror_candidate_chirho.as_ref(),
        ) {
            append_mirror_chirho
                .prepare_append_chirho(mirror_candidate_chirho)
                .map_err(
                    |error_chirho| JournalErrorChirho::MirrorPrepareRefusedChirho {
                        detail_chirho: error_chirho.to_string(),
                    },
                )?;
        }
        let mut bytes_chirho = line_chirho.clone().into_bytes();
        bytes_chirho.push(b'\n');
        self.storage_chirho
            .append_durable_chirho(&self.path_chirho, &bytes_chirho)
            .map_err(storage_error_chirho)?;
        // Live-state update inside the append borrow: no extra durable sync.
        let line_offset_chirho = self.tail_byte_len_chirho;
        self.tail_digest_chirho = stored_record_digest_chirho;
        for (leg_index_chirho, leg_chirho) in admitted_chirho.legs_chirho.iter().enumerate() {
            self.head_states_chirho.insert(
                leg_chirho.account_chirho.clone(),
                leg_chirho.post_chirho.clone(),
            );
            self.head_locators_chirho.insert(
                leg_chirho.account_chirho.clone(),
                crate::checkpoint_chirho::HeadLocatorChirho {
                    seq_chirho: admitted_chirho.seq_chirho,
                    leg_index_chirho: leg_index_chirho as u32,
                    line_offset_chirho,
                    line_len_chirho: line_chirho.len() as u64,
                    line_digest_chirho: self.tail_digest_chirho.clone(),
                    post_chirho: leg_chirho.post_chirho.clone(),
                },
            );
        }
        self.apply_supply_chirho(&admitted_chirho)?;
        self.apply_escrow_transition_chirho(&admitted_chirho)?;
        let record_digest_chirho = self.tail_digest_chirho.clone();
        self.apply_effect_receipt_transition_chirho(
            &admitted_chirho,
            &record_digest_chirho,
            effect_receipt_transition_chirho,
        )?;
        self.tail_seq_chirho = admitted_chirho.seq_chirho;
        self.tail_hlc_chirho = admitted_chirho.hlc_chirho.clone();
        self.tail_line_offset_chirho = line_offset_chirho;
        self.tail_line_len_chirho = line_chirho.len() as u64;
        self.tail_byte_len_chirho += line_chirho.len() as u64 + 1;
        self.tail_physical_byte_len_chirho = self.tail_byte_len_chirho;
        self.last_recorded_epoch_chirho = admitted_chirho.epoch_chirho;
        let receipt_chirho = AppendReceiptChirho {
            seq_chirho: admitted_chirho.seq_chirho,
            record_digest_chirho: self.tail_digest_chirho.clone(),
            hlc_chirho: admitted_chirho.hlc_chirho.clone(),
            epoch_first_record_chirho,
        };
        self.prune_effect_receipt_window_chirho();
        if let (Some(append_mirror_chirho), Some(mirror_candidate_chirho)) = (
            self.append_mirror_chirho.as_ref(),
            mirror_candidate_chirho.as_ref(),
        ) {
            if let Err(error_chirho) =
                append_mirror_chirho.finalize_append_chirho(mirror_candidate_chirho)
            {
                return Err(JournalErrorChirho::MirrorCommittedEvidencePendingChirho {
                    receipt_chirho: Box::new(receipt_chirho),
                    detail_chirho: error_chirho.to_string(),
                });
            }
        }
        Ok(receipt_chirho)
    }
}
