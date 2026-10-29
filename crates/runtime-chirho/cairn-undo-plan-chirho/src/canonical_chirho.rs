// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Schema-first canonical codecs and domain-separated addresses for the undo family.

use crate::contract_chirho::{
    validate_reversion_contract_chirho, validate_reversion_contract_set_chirho,
    BlessedReversionContractChirho, BlessedReversionContractSetChirho,
    MAX_COMPENSATION_CASCADE_DEPTH_CHIRHO, REVERSION_CONTRACT_SET_SCHEMA_CHIRHO,
};
use crate::framing_chirho::framed_blake3_hash_chirho;
use crate::plan_chirho::{validate_undo_plan_chirho, UndoPlanChirho, UNDO_PLAN_SCHEMA_CHIRHO};
use anyhow::{bail, Context, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use serde::Deserialize;

const CONTRACT_SET_DIGEST_DOMAIN_CHIRHO: &[u8] = b"cairn-blessed-reversion-contract-set-v1-chirho";
const CONTRACT_DIGEST_DOMAIN_CHIRHO: &[u8] = b"cairn-blessed-reversion-contract-v1-chirho";
const UNDO_PLAN_DIGEST_DOMAIN_CHIRHO: &[u8] = b"cairn-undo-plan-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UndoWireDocumentChirho {
    ContractSetChirho(BlessedReversionContractSetChirho),
    PlanChirho(UndoPlanChirho),
}

pub fn canonical_contract_set_bytes_chirho(
    set_chirho: &BlessedReversionContractSetChirho,
) -> Result<Vec<u8>> {
    validate_reversion_contract_set_chirho(set_chirho)?;
    serde_json::to_vec(set_chirho).context("encode canonical reversion contract set")
}

pub fn canonical_reversion_contract_bytes_chirho(
    contract_chirho: &BlessedReversionContractChirho,
) -> Result<Vec<u8>> {
    validate_reversion_contract_chirho(contract_chirho, MAX_COMPENSATION_CASCADE_DEPTH_CHIRHO)?;
    serde_json::to_vec(contract_chirho).context("encode canonical blessed-reversion contract")
}

pub fn canonical_undo_plan_bytes_chirho(plan_chirho: &UndoPlanChirho) -> Result<Vec<u8>> {
    validate_undo_plan_chirho(plan_chirho)?;
    serde_json::to_vec(plan_chirho).context("encode canonical undo plan")
}

pub fn contract_set_digest_chirho(
    set_chirho: &BlessedReversionContractSetChirho,
) -> Result<HashChirho> {
    let bytes_chirho = canonical_contract_set_bytes_chirho(set_chirho)?;
    framed_blake3_hash_chirho(CONTRACT_SET_DIGEST_DOMAIN_CHIRHO, &[&bytes_chirho])
}

pub fn reversion_contract_digest_chirho(
    contract_chirho: &BlessedReversionContractChirho,
) -> Result<HashChirho> {
    let bytes_chirho = canonical_reversion_contract_bytes_chirho(contract_chirho)?;
    framed_blake3_hash_chirho(CONTRACT_DIGEST_DOMAIN_CHIRHO, &[&bytes_chirho])
}

pub fn undo_plan_hash_chirho(plan_chirho: &UndoPlanChirho) -> Result<HashChirho> {
    let bytes_chirho = canonical_undo_plan_bytes_chirho(plan_chirho)?;
    framed_blake3_hash_chirho(UNDO_PLAN_DIGEST_DOMAIN_CHIRHO, &[&bytes_chirho])
}

pub fn parse_canonical_undo_document_chirho(text_chirho: &str) -> Result<UndoWireDocumentChirho> {
    #[derive(Deserialize)]
    struct UndoSchemaProbeChirho {
        schema_chirho: String,
    }

    let probe_chirho: UndoSchemaProbeChirho =
        serde_json::from_str(text_chirho).context("probe undo-family schema")?;
    match probe_chirho.schema_chirho.as_str() {
        REVERSION_CONTRACT_SET_SCHEMA_CHIRHO => Ok(UndoWireDocumentChirho::ContractSetChirho(
            parse_canonical_contract_set_chirho(text_chirho)?,
        )),
        UNDO_PLAN_SCHEMA_CHIRHO => Ok(UndoWireDocumentChirho::PlanChirho(
            parse_canonical_undo_plan_chirho(text_chirho)?,
        )),
        _ => bail!("unsupported undo-family schema"),
    }
}

pub fn parse_canonical_contract_set_chirho(
    text_chirho: &str,
) -> Result<BlessedReversionContractSetChirho> {
    let set_chirho: BlessedReversionContractSetChirho =
        serde_json::from_str(text_chirho).context("decode reversion contract set")?;
    // Exact equality is load-bearing: Serde may ignore extra fields on internally tagged unit
    // variants even when their enum declares deny_unknown_fields.
    let canonical_chirho = canonical_contract_set_bytes_chirho(&set_chirho)?;
    if canonical_chirho != text_chirho.as_bytes() {
        bail!("reversion contract set has a byte-canonical mismatch");
    }
    Ok(set_chirho)
}

pub fn parse_canonical_undo_plan_chirho(text_chirho: &str) -> Result<UndoPlanChirho> {
    let plan_chirho: UndoPlanChirho =
        serde_json::from_str(text_chirho).context("decode undo plan")?;
    let canonical_chirho = canonical_undo_plan_bytes_chirho(&plan_chirho)?;
    if canonical_chirho != text_chirho.as_bytes() {
        bail!("undo plan has a byte-canonical mismatch");
    }
    Ok(plan_chirho)
}
