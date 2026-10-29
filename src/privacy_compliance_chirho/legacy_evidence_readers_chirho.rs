// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Read-only legacy credit-hold and billing-compensation evidence readers, retained after the spine deletes.
//!
//! CF6-D2 brick (a1). These are the `load_*` readers a SUBJECT EXPORT actually reads, extracted out of
//! `src/economic_flows_chirho` so they survive that directory's deletion. The map's hazard for this
//! brick is not a compile break — it is that *"a successor returning different evidence changes what a
//! subject export CONTAINS"* — so the move is byte-exact and pinned by
//! `legacy_evidence_characterization_tests_chirho`.
//!
//! **Only the CLEAN half lives here, and that is deliberate.** Every `load_*` reader was measured free
//! of old-road/gate1 machinery; every `verify_*` reader reaches it. The `verify_*` half is brick (a2)
//! and needs the old-road dependencies dispositioned first, so extracting it here would drag
//! dual-write-era machinery into the module whose whole purpose is to be the clean retained thing.
//!
//! **This module must never depend on the spine.** It imports only the model crate and `std`; the spine
//! re-exports back from here during the transition, and that direction dies with the spine.

use crate::economic_model_chirho::billing_contract_chirho::verify_billing_record_schema_chirho;
use crate::economic_model_chirho::{
    BillingCompensationRecordChirho, CreditHoldRecordChirho,
    BILLING_COMPENSATION_RECORD_SCHEMA_CHIRHO, CREDIT_HOLD_RECORD_SCHEMA_CHIRHO,
};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

pub(crate) fn records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("credit-holds-chirho.jsonl")
}

pub(crate) fn validate_hold_record_schema_chirho(
    record_chirho: &CreditHoldRecordChirho,
) -> Result<()> {
    if !record_chirho.schema_chirho.is_empty()
        && record_chirho.schema_chirho != CREDIT_HOLD_RECORD_SCHEMA_CHIRHO
    {
        bail!(
            "credit hold record {} has unsupported schema '{}'",
            record_chirho.seq_chirho,
            record_chirho.schema_chirho
        );
    }
    Ok(())
}

/// Reads the credit-hold log as EVIDENCE. Deliberately validates only each row's schema.
///
/// **Do NOT add sequence-continuity or cross-record validation here.** That asymmetry against
/// `verified_credit_hold_states_chirho` is designed, not an oversight: a subject export must be able
/// to READ a damaged log in order to DISCLOSE it, while verification is what asserts the log is
/// whole. Unifying the two readers looks like an obvious cleanup and would break subject export for
/// exactly the damaged roots that most need disclosing — and every test using an intact corpus would
/// stay green while it happened.
///
/// Pinned by `legacy_evidence_characterization_tests_chirho::
/// verification_refuses_a_seq_gap_and_load_does_not_chirho`.
pub fn load_credit_holds_chirho(root_chirho: &Path) -> Result<Vec<CreditHoldRecordChirho>> {
    let path_chirho = records_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let record_chirho: CreditHoldRecordChirho = serde_json::from_str(line_chirho)?;
        validate_hold_record_schema_chirho(&record_chirho)?;
        records_chirho.push(record_chirho);
    }
    Ok(records_chirho)
}

pub(crate) fn compensation_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("billing-compensations-chirho.jsonl")
}

pub fn load_billing_compensations_chirho(
    root_chirho: &Path,
) -> Result<Vec<BillingCompensationRecordChirho>> {
    let path_chirho = compensation_records_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let record_chirho: BillingCompensationRecordChirho = serde_json::from_str(line_chirho)?;
        verify_billing_record_schema_chirho(
            &record_chirho.schema_chirho,
            BILLING_COMPENSATION_RECORD_SCHEMA_CHIRHO,
            "billing compensation record",
        )?;
        records_chirho.push(record_chirho);
    }
    Ok(records_chirho)
}
