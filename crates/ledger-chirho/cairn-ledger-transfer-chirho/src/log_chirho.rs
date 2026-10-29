// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The saga log: the coordinator's own root-signed chain (the third chain-core consumer) folded to
//! per-saga state machines. Torn-tail posture = RESUME-OR-COMPENSATE (#4901): a torn suffix is
//! truncated, never walked — safe because the intent is durable BEFORE the first journal append,
//! so a torn line is always either re-derivable from the journals' own laws or moot.

use crate::record_chirho::{
    canonical_saga_line_chirho, parse_canonical_saga_line_chirho, saga_root_signed_content_chirho,
    SagaDecisionChirho, SagaOpChirho, SagaOutcomeChirho, SagaRecordChirho, SagaStepEvidenceChirho,
    SagaStepPlanChirho, SAGA_CHAIN_DOMAIN_CHIRHO, SAGA_RECORD_SCHEMA_V1_CHIRHO,
};
use anyhow::{anyhow, bail, Result};
use cairn_chain_core_chirho::{
    chain_anchor_hex_chirho, walk_verified_chain_chirho, ChainFamilyChirho, ChainWalkErrorChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use std::collections::{BTreeMap, BTreeSet};

/// One saga's folded phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SagaPhaseChirho {
    /// Intent durable; holds in flight.
    HoldingChirho,
    /// Decision recorded; settle/release in flight.
    DecidedChirho {
        decision_chirho: SagaDecisionChirho,
    },
    ClosedChirho {
        outcome_chirho: SagaOutcomeChirho,
    },
}

/// One saga's folded state — everything resume needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SagaStateChirho {
    pub steps_chirho: Vec<SagaStepPlanChirho>,
    pub opened_at_ms_chirho: u64,
    pub ttl_ms_chirho: u64,
    pub phase_chirho: SagaPhaseChirho,
    /// Step numbers (1-based plan order) with a durable held record.
    pub held_chirho: BTreeSet<u32>,
    /// Step numbers with a durable settled/released record.
    pub consumed_chirho: BTreeSet<u32>,
}

impl SagaStateChirho {
    pub fn deadline_ms_chirho(&self) -> u64 {
        self.opened_at_ms_chirho.saturating_add(self.ttl_ms_chirho)
    }
}

/// The verified saga log: records + tail + the per-saga fold.
#[derive(Debug)]
pub struct VerifiedSagaLogChirho {
    pub records_chirho: Vec<SagaRecordChirho>,
    pub tail_digest_hex_chirho: String,
    pub sagas_chirho: BTreeMap<DigestChirho, SagaStateChirho>,
}

struct SagaChainFamilyChirho<'ports_chirho> {
    saga_log_id_chirho: &'ports_chirho str,
    root_chirho: &'ports_chirho dyn LedgerSignerPortChirho,
}

impl ChainFamilyChirho for SagaChainFamilyChirho<'_> {
    type RecordChirho = SagaRecordChirho;
    type ErrorChirho = anyhow::Error;

    fn parse_line_chirho(&self, line_chirho: &str) -> Result<SagaRecordChirho, anyhow::Error> {
        parse_canonical_saga_line_chirho(line_chirho)
    }

    fn seq_chirho(&self, record_chirho: &SagaRecordChirho) -> u64 {
        record_chirho.seq_chirho
    }

    fn prev_hex_chirho<'record_chirho>(
        &self,
        record_chirho: &'record_chirho SagaRecordChirho,
    ) -> &'record_chirho str {
        &record_chirho.prev_chirho
    }

    fn verify_record_chirho(&self, record_chirho: &SagaRecordChirho) -> Result<(), anyhow::Error> {
        if record_chirho.saga_log_id_chirho != self.saga_log_id_chirho {
            bail!(
                "record names saga log {} — cross-log replay refused",
                record_chirho.saga_log_id_chirho
            );
        }
        let signed_content_chirho = saga_root_signed_content_chirho(record_chirho)?;
        if !self
            .root_chirho
            .verify_chirho(&signed_content_chirho, &record_chirho.root_sig_chirho)
        {
            bail!(
                "saga root signature does not verify at seq {}",
                record_chirho.seq_chirho
            );
        }
        Ok(())
    }
}

/// Load the saga log with the RESUME-OR-COMPENSATE torn posture: a trailing partial line (no LF)
/// is TRUNCATED — the walk sees only complete lines — and the truncation is repaired durably so
/// the next append extends a clean tail. Missing object = an empty log.
pub fn load_saga_log_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    root_chirho: &dyn LedgerSignerPortChirho,
    path_chirho: &StoragePathChirho,
    saga_log_id_chirho: &str,
) -> Result<VerifiedSagaLogChirho> {
    let anchor_chirho = chain_anchor_hex_chirho(SAGA_CHAIN_DOMAIN_CHIRHO, saga_log_id_chirho);
    let Some(bytes_chirho) = storage_chirho
        .read_all_chirho(path_chirho)
        .map_err(|error_chirho| anyhow!("read saga log: {error_chirho}"))?
    else {
        return Ok(VerifiedSagaLogChirho {
            records_chirho: Vec::new(),
            tail_digest_hex_chirho: anchor_chirho,
            sagas_chirho: BTreeMap::new(),
        });
    };
    let clean_bytes_chirho = match bytes_chirho
        .iter()
        .rposition(|byte_chirho| *byte_chirho == b'\n')
    {
        Some(last_lf_chirho) if last_lf_chirho + 1 == bytes_chirho.len() => bytes_chirho,
        Some(last_lf_chirho) => {
            // Torn tail: keep the complete prefix, repair durably (resume-or-compensate — the
            // journals' own admission laws re-derive whatever the torn line was about to say).
            let clean_chirho = bytes_chirho[..=last_lf_chirho].to_vec();
            storage_chirho
                .atomic_write_chirho(path_chirho, &clean_chirho)
                .map_err(|error_chirho| anyhow!("repair torn saga tail: {error_chirho}"))?;
            clean_chirho
        }
        None => {
            // The whole object is one torn line — an empty log after repair.
            storage_chirho
                .atomic_write_chirho(path_chirho, b"")
                .map_err(|error_chirho| anyhow!("repair torn saga tail: {error_chirho}"))?;
            Vec::new()
        }
    };
    let text_chirho = std::str::from_utf8(&clean_bytes_chirho)
        .map_err(|_| anyhow!("saga log bytes are not UTF-8"))?;
    let family_chirho = SagaChainFamilyChirho {
        saga_log_id_chirho,
        root_chirho,
    };
    let (lines_chirho, tail_digest_hex_chirho) =
        walk_verified_chain_chirho(text_chirho, &anchor_chirho, &family_chirho).map_err(
            |error_chirho| match error_chirho {
                ChainWalkErrorChirho::DenseSeqChirho {
                    expected_chirho,
                    found_chirho,
                } => anyhow!("seq {found_chirho} where {expected_chirho} expected (dense law)"),
                ChainWalkErrorChirho::PrevBindingChirho { seq_chirho } => {
                    anyhow!("prev mismatch at seq {seq_chirho}")
                }
                ChainWalkErrorChirho::FamilyChirho { error_chirho } => error_chirho,
            },
        )?;
    let mut sagas_chirho: BTreeMap<DigestChirho, SagaStateChirho> = BTreeMap::new();
    let mut records_chirho = Vec::with_capacity(lines_chirho.len());
    for line_chirho in lines_chirho {
        fold_saga_op_chirho(
            &mut sagas_chirho,
            &line_chirho.record_chirho.saga_id_chirho,
            &line_chirho.record_chirho.op_chirho,
        )?;
        records_chirho.push(line_chirho.record_chirho);
    }
    Ok(VerifiedSagaLogChirho {
        records_chirho,
        tail_digest_hex_chirho,
        sagas_chirho,
    })
}

/// The saga op law, applied in chain order — fail-closed on any out-of-order op. The step-number
/// space is the 1-based plan order; Finalize requires EVERY step held; Closed requires every held
/// step consumed (finalize) or every held step released (abort).
fn fold_saga_op_chirho(
    sagas_chirho: &mut BTreeMap<DigestChirho, SagaStateChirho>,
    saga_id_chirho: &DigestChirho,
    op_chirho: &SagaOpChirho,
) -> Result<()> {
    match op_chirho {
        SagaOpChirho::IntentChirho {
            steps_chirho,
            opened_at_ms_chirho,
            ttl_ms_chirho,
            ..
        } => {
            if sagas_chirho.contains_key(saga_id_chirho) {
                bail!("duplicate saga intent for {}", saga_id_chirho.0);
            }
            sagas_chirho.insert(
                saga_id_chirho.clone(),
                SagaStateChirho {
                    steps_chirho: steps_chirho.clone(),
                    opened_at_ms_chirho: *opened_at_ms_chirho,
                    ttl_ms_chirho: *ttl_ms_chirho,
                    phase_chirho: SagaPhaseChirho::HoldingChirho,
                    held_chirho: BTreeSet::new(),
                    consumed_chirho: BTreeSet::new(),
                },
            );
        }
        SagaOpChirho::StepHeldChirho { step_chirho, .. } => {
            let state_chirho = known_saga_chirho(sagas_chirho, saga_id_chirho)?;
            if state_chirho.phase_chirho != SagaPhaseChirho::HoldingChirho {
                bail!("step-held after the decision phase");
            }
            require_planned_step_chirho(state_chirho, *step_chirho)?;
            if !state_chirho.held_chirho.insert(*step_chirho) {
                bail!("duplicate step-held for step {step_chirho}");
            }
        }
        SagaOpChirho::DecisionChirho { decision_chirho } => {
            let state_chirho = known_saga_chirho(sagas_chirho, saga_id_chirho)?;
            if state_chirho.phase_chirho != SagaPhaseChirho::HoldingChirho {
                bail!("duplicate decision");
            }
            if *decision_chirho == SagaDecisionChirho::FinalizeChirho
                && state_chirho.held_chirho.len() != state_chirho.steps_chirho.len()
            {
                bail!("finalize decision before every step is held");
            }
            state_chirho.phase_chirho = SagaPhaseChirho::DecidedChirho {
                decision_chirho: decision_chirho.clone(),
            };
        }
        SagaOpChirho::StepSettledChirho { step_chirho, .. } => {
            let state_chirho = known_saga_chirho(sagas_chirho, saga_id_chirho)?;
            let SagaPhaseChirho::DecidedChirho {
                decision_chirho: SagaDecisionChirho::FinalizeChirho,
            } = &state_chirho.phase_chirho
            else {
                bail!("step-settled without a finalize decision");
            };
            require_planned_step_chirho(state_chirho, *step_chirho)?;
            if !state_chirho.held_chirho.contains(step_chirho) {
                bail!("step-settled for a step never held");
            }
            if !state_chirho.consumed_chirho.insert(*step_chirho) {
                bail!("duplicate step-settled for step {step_chirho}");
            }
        }
        SagaOpChirho::StepReleasedChirho { step_chirho, .. } => {
            let state_chirho = known_saga_chirho(sagas_chirho, saga_id_chirho)?;
            let SagaPhaseChirho::DecidedChirho {
                decision_chirho: SagaDecisionChirho::AbortChirho { .. },
            } = &state_chirho.phase_chirho
            else {
                bail!("step-released without an abort decision");
            };
            require_planned_step_chirho(state_chirho, *step_chirho)?;
            if !state_chirho.consumed_chirho.insert(*step_chirho) {
                bail!("duplicate step-released for step {step_chirho}");
            }
        }
        SagaOpChirho::ClosedChirho { outcome_chirho } => {
            let state_chirho = known_saga_chirho(sagas_chirho, saga_id_chirho)?;
            let SagaPhaseChirho::DecidedChirho { decision_chirho } = &state_chirho.phase_chirho
            else {
                bail!("closed without a decision");
            };
            match (decision_chirho, outcome_chirho) {
                (SagaDecisionChirho::FinalizeChirho, SagaOutcomeChirho::FinalizedChirho) => {
                    if state_chirho.consumed_chirho != state_chirho.held_chirho {
                        bail!("closed finalized before every held step settled");
                    }
                }
                (SagaDecisionChirho::AbortChirho { .. }, SagaOutcomeChirho::CompensatedChirho) => {
                    // Every RELEASED step was recorded in consumed; a held step missing from
                    // consumed means its release was never durably evidenced.
                    if !state_chirho
                        .held_chirho
                        .is_subset(&state_chirho.consumed_chirho)
                    {
                        bail!("closed compensated before every held step released");
                    }
                }
                _ => bail!("closed outcome contradicts the decision"),
            }
            state_chirho.phase_chirho = SagaPhaseChirho::ClosedChirho {
                outcome_chirho: outcome_chirho.clone(),
            };
        }
    }
    Ok(())
}

fn known_saga_chirho<'state_chirho>(
    sagas_chirho: &'state_chirho mut BTreeMap<DigestChirho, SagaStateChirho>,
    saga_id_chirho: &DigestChirho,
) -> Result<&'state_chirho mut SagaStateChirho> {
    let Some(state_chirho) = sagas_chirho.get_mut(saga_id_chirho) else {
        bail!("op for unknown saga {}", saga_id_chirho.0);
    };
    if let SagaPhaseChirho::ClosedChirho { .. } = state_chirho.phase_chirho {
        bail!("op for closed saga {}", saga_id_chirho.0);
    }
    Ok(state_chirho)
}

fn require_planned_step_chirho(state_chirho: &SagaStateChirho, step_chirho: u32) -> Result<()> {
    let planned_chirho =
        step_chirho >= 1 && (step_chirho as usize) <= state_chirho.steps_chirho.len();
    if !planned_chirho {
        bail!("step {step_chirho} is not in the saga's plan");
    }
    Ok(())
}

/// Append one saga op: verified load (which also repairs a torn tail), fold precondition, build →
/// root-sign → ONE durable append. Configuration-rate O(n) load is acceptable at this increment;
/// the coordinator batches its appends per phase.
pub fn append_saga_op_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    root_chirho: &dyn LedgerSignerPortChirho,
    path_chirho: &StoragePathChirho,
    saga_log_id_chirho: &str,
    saga_id_chirho: &DigestChirho,
    op_chirho: SagaOpChirho,
) -> Result<SagaRecordChirho> {
    let verified_chirho =
        load_saga_log_chirho(storage_chirho, root_chirho, path_chirho, saga_log_id_chirho)?;
    let mut preview_chirho = verified_chirho.sagas_chirho.clone();
    fold_saga_op_chirho(&mut preview_chirho, saga_id_chirho, &op_chirho)?;
    let mut record_chirho = SagaRecordChirho {
        schema_chirho: SAGA_RECORD_SCHEMA_V1_CHIRHO.to_string(),
        seq_chirho: verified_chirho.records_chirho.len() as u64,
        prev_chirho: verified_chirho.tail_digest_hex_chirho.clone(),
        saga_log_id_chirho: saga_log_id_chirho.to_string(),
        saga_id_chirho: saga_id_chirho.clone(),
        op_chirho,
        root_sig_chirho: String::new(),
    };
    let signed_content_chirho = saga_root_signed_content_chirho(&record_chirho)?;
    record_chirho.root_sig_chirho = root_chirho
        .sign_chirho(&signed_content_chirho)
        .map_err(|error_chirho| anyhow!("sign saga record: {error_chirho}"))?;
    let line_chirho = canonical_saga_line_chirho(&record_chirho)?;
    let mut bytes_chirho = line_chirho.into_bytes();
    bytes_chirho.push(b'\n');
    storage_chirho
        .append_durable_chirho(path_chirho, &bytes_chirho)
        .map_err(|error_chirho| anyhow!("append saga record: {error_chirho}"))?;
    Ok(record_chirho)
}

/// The receipt evidence for a live journal append (the b-ii evidence shape).
pub fn receipt_evidence_chirho(
    receipt_chirho: &cairn_ledger_log_chirho::journal_chirho::AppendReceiptChirho,
) -> SagaStepEvidenceChirho {
    SagaStepEvidenceChirho::ReceiptChirho {
        seq_chirho: receipt_chirho.seq_chirho,
        record_digest_chirho: receipt_chirho.record_digest_chirho.clone(),
        hlc_chirho: receipt_chirho.hlc_chirho.clone(),
    }
}
