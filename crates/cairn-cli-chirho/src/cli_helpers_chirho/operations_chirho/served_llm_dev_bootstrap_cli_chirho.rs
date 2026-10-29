// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Dev-only served-LLM ledger bootstrap porcelain. The command adds no storage-layout or money-
//! authority grammar of its own: it forwards the four operator coordinates to the bootstrap crate,
//! which authors a test-kind config/plan/activation and drives the single-node regenesis mint, then
//! prints the resulting non-secret report.

use crate::args_chirho::CommandChirho;
use cairn_served_llm_dev_bootstrap_chirho::{
    run_served_llm_dev_bootstrap_chirho, ServedLlmDevBootstrapRequestChirho,
};
use std::path::Path;

pub(crate) fn handle_served_llm_dev_bootstrap_command_chirho(
    selected_root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    let CommandChirho::ServedLlmDevBootstrapChirho(args_chirho) = command_chirho else {
        return Ok(false);
    };
    let report_chirho = run_served_llm_dev_bootstrap_chirho(ServedLlmDevBootstrapRequestChirho {
        root_chirho: selected_root_chirho,
        payer_principal_chirho: &args_chirho.payer_principal_chirho,
        owner_principal_chirho: &args_chirho.owner_principal_chirho,
        amount_chirho: args_chirho.amount_chirho,
        billing_kind_chirho: &args_chirho.billing_kind_chirho,
    })?;
    println!("{}", serde_json::to_string(&report_chirho)?);
    Ok(true)
}
