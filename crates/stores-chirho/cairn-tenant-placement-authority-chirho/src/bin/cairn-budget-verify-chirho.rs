// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! What does this root's prepaid test-credit budget actually say, and what does it owe a release?
//!
//! CF8 clause 11's residual named three things — signed principals/evidence, a durable adapter, and a
//! production caller rather than caller-supplied in-memory values. This is the third: the budget it
//! reports is REPLAYED from signed events on disk, so no balance here was handed in by whoever asked.
//!
//! It reads. Nothing is reserved, settled or released, and it could not release anything if it wanted
//! to — the store verifies and cannot sign, because a component that could author a release could
//! author a settlement.
//!
//! `awaiting_release_chirho` is the operationally useful half: reservations past their deadline that
//! the log has not resolved, which is exactly the list an operator must sign releases for after a
//! crash. Re-running this after appending those releases returns a shorter list, because the log is
//! what says it already happened — there is no recovery flag to get out of step with reality.
//!
//! ```text
//! cairn-budget-verify-chirho <evidence-root> <budget-authority-root> <budget-id> <now-millis>
//! ```

use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::budget_event_store_chirho::{
    budget_authority_key_id_chirho, build_budget_report_chirho, render_budget_report_chirho,
};
use cairn_tenant_placement_authority_chirho::control_plane_authorities_chirho::single_role_verifier_chirho;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE_REFUSAL_CHIRHO: &str = "BudgetVerifyUsageRefusedChirho";

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
    let root_chirho = PathBuf::from(next_utf8_chirho(&mut arguments_chirho)?);
    let budget_authority_root_chirho = PathBuf::from(next_utf8_chirho(&mut arguments_chirho)?);
    let budget_id_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    let now_millis_chirho = next_utf8_chirho(&mut arguments_chirho)?
        .parse::<u64>()
        .map_err(|_error_chirho| USAGE_REFUSAL_CHIRHO.to_string())?;
    if arguments_chirho.next().is_some() {
        return Err(USAGE_REFUSAL_CHIRHO.to_string());
    }

    let authority_key_chirho =
        budget_authority_key_id_chirho(&root_chirho, &budget_authority_root_chirho)
            .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;
    let authority_chirho = single_role_verifier_chirho(&authority_key_chirho)
        .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;
    let report_chirho = build_budget_report_chirho(
        &root_chirho,
        &budget_authority_root_chirho,
        &budget_id_chirho,
        now_millis_chirho,
        &authority_chirho,
    )
    .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;
    render_budget_report_chirho(&report_chirho)
        .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))
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
