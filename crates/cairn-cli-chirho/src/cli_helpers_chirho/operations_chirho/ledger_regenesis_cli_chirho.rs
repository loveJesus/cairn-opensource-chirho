// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Thin operator-only H3 porcelain. Every money and storage coordinate comes from the reviewed
//! plan/config pair; the command adds no amount, path, or create-authority grammar of its own.

use crate::args_chirho::CommandChirho;
use cairn_ledger_regenesis_chirho::{
    run_ledger_regenesis_chirho, LedgerRegenesisH3aRequestChirho,
    LedgerRegenesisPublicationProofChirho, PublishedLedgerRegenesisStageChirho,
};
use serde::Serialize;
use std::path::Path;

pub const LEDGER_REGENESIS_CLI_REPORT_SCHEMA_V2_CHIRHO: &str =
    "ledger-regenesis-cli-report-v2-chirho";

#[derive(Debug, Serialize)]
struct LedgerRegenesisCliReportV2Chirho {
    schema_chirho: &'static str,
    plan_digest_chirho: String,
    packet_digest_chirho: String,
    publication_manifest_digest_chirho: String,
    final_parent_name_chirho: String,
    publication_proof_chirho: LedgerRegenesisPublicationProofChirho,
}

fn ledger_regenesis_report_chirho(
    receipt_chirho: PublishedLedgerRegenesisStageChirho,
) -> LedgerRegenesisCliReportV2Chirho {
    LedgerRegenesisCliReportV2Chirho {
        schema_chirho: LEDGER_REGENESIS_CLI_REPORT_SCHEMA_V2_CHIRHO,
        plan_digest_chirho: receipt_chirho.plan_digest_chirho,
        packet_digest_chirho: receipt_chirho.packet_digest_chirho,
        publication_manifest_digest_chirho: receipt_chirho.publication_manifest_digest_chirho,
        final_parent_name_chirho: receipt_chirho.final_parent_name_chirho,
        publication_proof_chirho: receipt_chirho.publication_proof_chirho,
    }
}

pub(crate) fn handle_ledger_regenesis_command_chirho(
    selected_root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    let CommandChirho::LedgerRegenesisChirho(args_chirho) = command_chirho else {
        return Ok(false);
    };
    let receipt_chirho = run_ledger_regenesis_chirho(LedgerRegenesisH3aRequestChirho {
        selected_root_chirho,
        config_path_chirho: &args_chirho.config_path_chirho,
        plan_path_chirho: &args_chirho.plan_path_chirho,
        expected_plan_digest_chirho: &args_chirho.expected_plan_digest_chirho,
        issuer_secret_name_chirho: &args_chirho.issuer_secret_name_chirho,
        activation_authorization_path_chirho: &args_chirho.activation_authorization_path_chirho,
        expected_activation_authorization_digest_chirho: &args_chirho
            .expected_activation_authorization_digest_chirho,
    })?;
    let report_chirho = ledger_regenesis_report_chirho(receipt_chirho);
    println!("{}", serde_json::to_string(&report_chirho)?);
    Ok(true)
}

#[cfg(test)]
#[path = "ledger_regenesis_cli_chirho_tests.rs"]
mod ledger_regenesis_cli_tests_chirho;
