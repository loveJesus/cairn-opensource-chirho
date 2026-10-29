// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Verify and append one externally signed prepaid-budget event.
//!
//! The authority key comes from funding genesis in the separately custodied checkpoint. The command
//! cannot replace that trust coordinate, supply a ceiling, or repair through a read surface.

use cairn_placement_chirho::budget_chirho::budget_event_attestation_chirho::BudgetEventAttestationChirho;
use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::budget_event_store_chirho::{
    append_verified_budget_event_chirho, budget_authority_key_id_chirho,
    BUDGET_EVENT_LINE_MAX_BYTES_CHIRHO,
};
use cairn_tenant_placement_authority_chirho::control_plane_authorities_chirho::single_role_verifier_chirho;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE_REFUSAL_CHIRHO: &str = "BudgetEventAppendUsageRefusedChirho";
const RECORD_UNREADABLE_REFUSAL_CHIRHO: &str = "BudgetEventRecordFileUnreadableChirho";
const RECORD_MALFORMED_REFUSAL_CHIRHO: &str = "BudgetEventRecordFileMalformedChirho";

fn next_utf8_chirho(
    arguments_chirho: &mut impl Iterator<Item = OsString>,
) -> Result<String, &'static str> {
    arguments_chirho
        .next()
        .ok_or(USAGE_REFUSAL_CHIRHO)?
        .into_string()
        .map_err(|_value_chirho| USAGE_REFUSAL_CHIRHO)
}

fn run_chirho() -> Result<String, String> {
    let mut arguments_chirho = std::env::args_os();
    let _program_chirho = arguments_chirho.next();
    let evidence_root_chirho = PathBuf::from(next_utf8_chirho(&mut arguments_chirho)?);
    let authority_root_chirho = PathBuf::from(next_utf8_chirho(&mut arguments_chirho)?);
    let record_path_chirho = PathBuf::from(next_utf8_chirho(&mut arguments_chirho)?);
    if arguments_chirho.next().is_some() {
        return Err(USAGE_REFUSAL_CHIRHO.to_string());
    }

    let bytes_chirho = cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        &record_path_chirho,
        BUDGET_EVENT_LINE_MAX_BYTES_CHIRHO as u64,
    )
    .map_err(|_error_chirho| RECORD_UNREADABLE_REFUSAL_CHIRHO.to_string())?;
    let record_chirho: BudgetEventAttestationChirho = serde_json::from_slice(&bytes_chirho)
        .map_err(|_error_chirho| RECORD_MALFORMED_REFUSAL_CHIRHO.to_string())?;
    let authority_key_chirho =
        budget_authority_key_id_chirho(&evidence_root_chirho, &authority_root_chirho)
            .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;
    let authority_chirho = single_role_verifier_chirho(&authority_key_chirho)
        .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;
    append_verified_budget_event_chirho(
        &evidence_root_chirho,
        &authority_root_chirho,
        &record_chirho,
        &authority_chirho,
    )
    .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;
    Ok(format!(
        "budget_id_chirho={} reservation_id_chirho={} event_seq_chirho={}",
        record_chirho.intent_chirho.budget_id_chirho,
        record_chirho.intent_chirho.reservation_id_chirho,
        record_chirho.intent_chirho.event_seq_chirho
    ))
}

fn main() -> ExitCode {
    match run_chirho() {
        Ok(rendered_chirho) => {
            println!("{rendered_chirho}");
            ExitCode::SUCCESS
        }
        Err(identity_chirho) => {
            eprintln!("{identity_chirho}");
            ExitCode::FAILURE
        }
    }
}
