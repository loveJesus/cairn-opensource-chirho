// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Repair one checkpoint-ahead budget append without requiring a new spend.
//!
//! This is an explicit write-authority road, separate from report and verify. It blocks on the root
//! lock, re-reads durable state inside that lock, and only appends the exact checkpointed line.

use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::budget_event_store_chirho::{
    budget_authority_key_id_chirho, repair_budget_log_chirho,
};
use cairn_tenant_placement_authority_chirho::control_plane_authorities_chirho::single_role_verifier_chirho;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE_REFUSAL_CHIRHO: &str = "BudgetRepairUsageRefusedChirho";

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
    if arguments_chirho.next().is_some() {
        return Err(USAGE_REFUSAL_CHIRHO.to_string());
    }

    let authority_key_chirho =
        budget_authority_key_id_chirho(&evidence_root_chirho, &authority_root_chirho)
            .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;
    let authority_chirho = single_role_verifier_chirho(&authority_key_chirho)
        .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;
    let outcome_chirho = repair_budget_log_chirho(
        &evidence_root_chirho,
        &authority_root_chirho,
        &authority_chirho,
    )
    .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;
    serde_json::to_string(&outcome_chirho)
        .map_err(|_error_chirho| "BudgetRepairOutcomeEncodeRefusedChirho".to_string())
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
