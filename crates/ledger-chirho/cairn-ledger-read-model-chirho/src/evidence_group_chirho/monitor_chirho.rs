// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! CF7 §6: the CONSERVATION MONITOR as a dogfood projection — OBSERVATIONAL EVIDENCE ONLY
//! (claude #5057 boundary, binding: an alarm may fail things CLOSED — halt feeds, page the
//! operator — but never opens or gates money; the admission fences remain the only money gates).
//!
//! Two pieces: (1) `SupplyFoldChirho`, the canonical per-kind supply projection (an ordinary
//! state fold over the journal's verified aggregate — the monitor rides the same
//! feed/receipt/canary/publication path as every projection); (2) `conservation_check_chirho`,
//! the pairwise law between two published supply views: for every kind, the VIEW delta must
//! equal the record-recomputed mint-minus-burn over the interval — computed here by a SECOND,
//! deliberately independent coding of the §11.3 supply law (the money-audit pattern: a shared
//! coding would let one bug agree with itself). The interval's records come from the read-only
//! recomposed stream BOUND to the live verified chain by the digest walk, and BOTH receipts'
//! cuts get REAL interior-ancestry verification against that walk (the digest at each receipt's
//! seq must equal the receipt's bound tail-line digest) — stronger than serving's equal-seq net,
//! free here because the monitor walks the interval anyway (rebuild-class O(n) by declared cost).

use crate::feeder_chirho::{
    verify_follow_receipt_chirho, view_bytes_digest_hex_chirho, MaterializedProjectionChirho,
    ProjectionFoldPortChirho, ProjectionSourceChirho, VerifiedSourceStateChirho,
};
use crate::localphaseb_evidence_chirho::{
    verified_journal_walk_chirho, walk_line_digest_at_seq_chirho,
};
use anyhow::{bail, Context, Result};
use cairn_ledger_log_chirho::ports_chirho::LedgerSignerPortChirho;
use cairn_ledger_model_chirho::record_chirho::LedgerOpChirho;
use std::collections::BTreeMap;

/// The canonical per-kind supply projection: `supply_by_kind` as canonical JSON
/// (`BTreeMap<kind, u64>` — deterministic by construction).
pub struct SupplyFoldChirho;

impl ProjectionFoldPortChirho for SupplyFoldChirho {
    fn fold_chirho(&self, source_chirho: &VerifiedSourceStateChirho<'_>) -> Result<Vec<u8>> {
        let supply_chirho: BTreeMap<String, u64> = source_chirho
            .journal_chirho
            .supply_by_kind_chirho()
            .iter()
            .map(|(kind_chirho, amount_chirho)| (kind_chirho.0.clone(), *amount_chirho))
            .collect();
        serde_json::to_vec(&supply_chirho).context("encode supply view")
    }
}

/// One unexplained per-kind supply movement — the alarm the operator pages on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConservationAlarmChirho {
    pub kind_chirho: String,
    pub view_delta_chirho: i128,
    pub records_delta_chirho: i128,
}

/// The pairwise check's evidence-carrying outcome. `alarms_chirho` empty = conserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConservationReportChirho {
    pub prev_seq_chirho: u64,
    pub next_seq_chirho: u64,
    pub kinds_checked_chirho: u64,
    pub alarms_chirho: Vec<ConservationAlarmChirho>,
}

/// Check conservation between two PUBLISHED supply views of the same projection over the same
/// journal instance. Evidence failures (receipts, bindings, ancestry) are `Err` — the caller
/// cannot tell conserved from broken-evidence by mistake; only a VERIFIED comparison yields a
/// report, and only a report with alarms means the supply moved without mint/burn warrant.
pub fn conservation_check_chirho(
    prev_chirho: &MaterializedProjectionChirho,
    next_chirho: &MaterializedProjectionChirho,
    feeder_root_chirho: &dyn LedgerSignerPortChirho,
    source_chirho: ProjectionSourceChirho<'_>,
) -> Result<ConservationReportChirho> {
    // Receipt + binding laws for BOTH cuts.
    verify_follow_receipt_chirho(&prev_chirho.receipt_chirho, feeder_root_chirho)
        .context("prev receipt")?;
    verify_follow_receipt_chirho(&next_chirho.receipt_chirho, feeder_root_chirho)
        .context("next receipt")?;
    for (label_chirho, materialized_chirho) in [("prev", prev_chirho), ("next", next_chirho)] {
        if view_bytes_digest_hex_chirho(&materialized_chirho.view_bytes_chirho)
            != materialized_chirho.receipt_chirho.view_digest_hex_chirho
        {
            bail!("{label_chirho} view bytes do not re-hash to the receipt binding");
        }
    }
    if prev_chirho.receipt_chirho.projection_name_chirho
        != next_chirho.receipt_chirho.projection_name_chirho
    {
        bail!("the two cuts name different projections");
    }
    if prev_chirho.receipt_chirho.source_genesis_digest_chirho
        != next_chirho.receipt_chirho.source_genesis_digest_chirho
    {
        bail!("the two cuts name different journal instances");
    }
    let prev_seq_chirho = prev_chirho.receipt_chirho.source_tail_seq_chirho;
    let next_seq_chirho = next_chirho.receipt_chirho.source_tail_seq_chirho;
    if prev_seq_chirho > next_seq_chirho {
        bail!("prev cut is beyond next cut — swap the arguments");
    }

    // The live chain: the SHARED verified canonical walk (the single-source census law — this
    // conservation monitor is its FIRST consumer, so the existing monitor tests prove the helper;
    // the credits-demo LocalPhaseB support read is the second consumer of the SAME
    // verified_journal_walk_chirho — no second parser), with INTERIOR ancestry for both cuts.
    let walk_chirho = verified_journal_walk_chirho(source_chirho)?;
    if walk_chirho.genesis_digest_chirho != prev_chirho.receipt_chirho.source_genesis_digest_chirho
    {
        bail!("live journal is a different instance than the receipts' cuts");
    }
    if next_seq_chirho > walk_chirho.tail_seq_chirho {
        bail!("next cut is beyond the live verified prefix");
    }
    // INTERIOR ANCESTRY: each receipt's bound tail-line digest must be the walked digest at its
    // seq (seq 0 = the genesis instance digest).
    for (label_chirho, seq_chirho, receipt_digest_chirho) in [
        (
            "prev",
            prev_seq_chirho,
            &prev_chirho.receipt_chirho.source_tail_line_digest_chirho,
        ),
        (
            "next",
            next_seq_chirho,
            &next_chirho.receipt_chirho.source_tail_line_digest_chirho,
        ),
    ] {
        let walked_chirho = walk_line_digest_at_seq_chirho(&walk_chirho, seq_chirho)?;
        if receipt_digest_chirho != walked_chirho {
            bail!(
                "{label_chirho} cut's bound line digest is NOT an ancestor of the live chain \
                 (interior rewrite or forged cut)"
            );
        }
    }

    // Parse both supply views (the monitor checks its OWN canonical fold format).
    let prev_supply_chirho: BTreeMap<String, u64> =
        serde_json::from_slice(&prev_chirho.view_bytes_chirho)
            .context("prev view is not a canonical supply view")?;
    let next_supply_chirho: BTreeMap<String, u64> =
        serde_json::from_slice(&next_chirho.view_bytes_chirho)
            .context("next view is not a canonical supply view")?;

    // The INDEPENDENT recomputation of §11.3 over the interval (prev, next]: Mint adds its single
    // leg's amount to the kind, Burn subtracts it, every other op moves no supply.
    let mut records_delta_chirho: BTreeMap<String, i128> = BTreeMap::new();
    for (record_chirho, _) in &walk_chirho.records_chirho {
        if record_chirho.seq_chirho <= prev_seq_chirho || record_chirho.seq_chirho > next_seq_chirho
        {
            continue;
        }
        match &record_chirho.op_chirho {
            LedgerOpChirho::MintChirho { .. } => {
                let leg_chirho = &record_chirho.legs_chirho[0];
                *records_delta_chirho
                    .entry(leg_chirho.account_chirho.kind_id_chirho.0.clone())
                    .or_insert(0) += i128::from(leg_chirho.amount_chirho);
            }
            LedgerOpChirho::BurnChirho { .. } => {
                let leg_chirho = &record_chirho.legs_chirho[0];
                *records_delta_chirho
                    .entry(leg_chirho.account_chirho.kind_id_chirho.0.clone())
                    .or_insert(0) -= i128::from(leg_chirho.amount_chirho);
            }
            _ => {}
        }
    }

    // Compare per kind across the union of both views and the recomputed deltas.
    let mut kinds_chirho: std::collections::BTreeSet<&String> = std::collections::BTreeSet::new();
    kinds_chirho.extend(prev_supply_chirho.keys());
    kinds_chirho.extend(next_supply_chirho.keys());
    kinds_chirho.extend(records_delta_chirho.keys());
    let mut alarms_chirho = Vec::new();
    let kinds_checked_chirho = kinds_chirho.len() as u64;
    for kind_chirho in kinds_chirho {
        let view_delta_chirho = i128::from(*next_supply_chirho.get(kind_chirho).unwrap_or(&0))
            - i128::from(*prev_supply_chirho.get(kind_chirho).unwrap_or(&0));
        let recomputed_chirho = *records_delta_chirho.get(kind_chirho).unwrap_or(&0);
        if view_delta_chirho != recomputed_chirho {
            alarms_chirho.push(ConservationAlarmChirho {
                kind_chirho: kind_chirho.clone(),
                view_delta_chirho,
                records_delta_chirho: recomputed_chirho,
            });
        }
    }
    Ok(ConservationReportChirho {
        prev_seq_chirho,
        next_seq_chirho,
        kinds_checked_chirho,
        alarms_chirho,
    })
}

#[cfg(test)]
#[path = "monitor_chirho/monitor_tests_chirho.rs"]
mod monitor_tests_chirho;
