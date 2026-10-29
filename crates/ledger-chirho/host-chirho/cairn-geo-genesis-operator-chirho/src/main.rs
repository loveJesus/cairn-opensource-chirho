// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The geo-genesis operator's read-only command line: verify a plan or a dry-run packet and print one
//! JSON report line on stdout. A refusal prints one JSON refusal line on stderr and exits 1, and a usage
//! error exits 2. No line carries a path, a key or a file byte.

use cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho;
use cairn_geo_genesis_operator_chirho::{
    verify_dry_run_report_chirho, verify_plan_report_chirho, OperatorRefusalChirho,
    OPERATOR_INPUT_MAX_BYTES_CHIRHO, REFUSAL_SCHEMA_CHIRHO,
};
use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

const VERSION_LINE_CHIRHO: &str =
    cairn_build_identity_chirho::version_line_chirho!("cairn-geo-genesis-operator-chirho");

const USAGE_CHIRHO: &str = "\
usage: cairn-geo-genesis-operator-chirho verify-plan-chirho \
--plan-chirho <plan.json> --ledger-plan-chirho <reviewed-ledger-plan.json> \
--plan-authority-key-chirho <hex> --acceptance-authority-key-chirho <hex>
       cairn-geo-genesis-operator-chirho verify-dry-run-chirho --packet-chirho <packet.json>
       cairn-geo-genesis-operator-chirho --version
  Read-only: it verifies and reports; it creates, reserves, signs and starts nothing.";

fn main() -> ExitCode {
    let args_chirho: Vec<OsString> = std::env::args_os().skip(1).collect();
    let first_chirho = args_chirho
        .first()
        .and_then(|arg_chirho| arg_chirho.to_str());
    if cairn_build_identity_chirho::is_version_request_chirho(first_chirho) {
        println!("{VERSION_LINE_CHIRHO}");
        return ExitCode::SUCCESS;
    }
    let outcome_chirho = match first_chirho {
        Some("verify-plan-chirho") => {
            match flags_chirho(
                &args_chirho[1..],
                &[
                    "--plan-chirho",
                    "--ledger-plan-chirho",
                    "--plan-authority-key-chirho",
                    "--acceptance-authority-key-chirho",
                ],
            ) {
                Ok(values_chirho) => run_verify_plan_chirho(&values_chirho),
                Err(usage_chirho) => return usage_exit_chirho(&usage_chirho),
            }
        }
        Some("verify-dry-run-chirho") => {
            match flags_chirho(&args_chirho[1..], &["--packet-chirho"]) {
                Ok(values_chirho) => run_verify_dry_run_chirho(&values_chirho),
                Err(usage_chirho) => return usage_exit_chirho(&usage_chirho),
            }
        }
        _ => return usage_exit_chirho("a command is required"),
    };
    match outcome_chirho {
        Ok(report_line_chirho) => {
            println!("{report_line_chirho}");
            ExitCode::SUCCESS
        }
        Err(refusal_chirho) => {
            eprintln!(
                "{}",
                serde_json::json!({
                    "schema_chirho": REFUSAL_SCHEMA_CHIRHO,
                    "refusal_chirho": refusal_chirho.identity_chirho(),
                })
            );
            ExitCode::from(1)
        }
    }
}

fn run_verify_plan_chirho(values_chirho: &[String]) -> Result<String, OperatorRefusalChirho> {
    let plan_chirho = read_input_chirho(&values_chirho[0], "--plan-chirho")?;
    let ledger_plan_chirho = read_input_chirho(&values_chirho[1], "--ledger-plan-chirho")?;
    let report_chirho = verify_plan_report_chirho(
        &plan_chirho,
        &ledger_plan_chirho,
        &values_chirho[2],
        &values_chirho[3],
    )?;
    Ok(serde_json::to_string(&report_chirho).expect("a plan report serializes"))
}

fn run_verify_dry_run_chirho(values_chirho: &[String]) -> Result<String, OperatorRefusalChirho> {
    let packet_chirho = read_input_chirho(&values_chirho[0], "--packet-chirho")?;
    let report_chirho = verify_dry_run_report_chirho(&packet_chirho)?;
    Ok(serde_json::to_string(&report_chirho).expect("a dry-run report serializes"))
}

/// One input file, read as a bounded single-link regular file; a failure names the flag, never the path.
fn read_input_chirho(
    path_chirho: &str,
    input_chirho: &'static str,
) -> Result<Vec<u8>, OperatorRefusalChirho> {
    read_identity_stable_bounded_regular_file_chirho(
        Path::new(path_chirho),
        OPERATOR_INPUT_MAX_BYTES_CHIRHO,
    )
    .map_err(|_error_chirho| OperatorRefusalChirho::InputUnreadableChirho { input_chirho })
}

/// The value of each named flag, in the order named. Every flag is required, and each appears once.
/// A problem names a known flag or an argument's position, never an argument the operator typed,
/// because a misplaced argument may be a path or a key.
fn flags_chirho(args_chirho: &[OsString], names_chirho: &[&str]) -> Result<Vec<String>, String> {
    let mut values_chirho: Vec<Option<String>> = vec![None; names_chirho.len()];
    let mut iter_chirho = args_chirho.iter().enumerate();
    while let Some((position_chirho, raw_flag_chirho)) = iter_chirho.next() {
        let argument_number_chirho = position_chirho + 1;
        let flag_chirho = raw_flag_chirho.to_str().ok_or_else(|| {
            format!("argument {argument_number_chirho} after the command is not valid UTF-8")
        })?;
        let index_chirho = names_chirho
            .iter()
            .position(|name_chirho| *name_chirho == flag_chirho)
            .ok_or_else(|| {
                format!(
                    "argument {argument_number_chirho} after the command is not one of its flags"
                )
            })?;
        let value_chirho = iter_chirho
            .next()
            .and_then(|(_position_chirho, value_chirho)| value_chirho.to_str())
            .ok_or_else(|| format!("{flag_chirho} needs a UTF-8 value"))?;
        if values_chirho[index_chirho].is_some() {
            return Err(format!("{flag_chirho} was supplied more than once"));
        }
        values_chirho[index_chirho] = Some(value_chirho.to_string());
    }
    names_chirho
        .iter()
        .zip(values_chirho)
        .map(|(name_chirho, value_chirho)| {
            value_chirho.ok_or_else(|| format!("{name_chirho} is required"))
        })
        .collect()
}

fn usage_exit_chirho(problem_chirho: &str) -> ExitCode {
    eprintln!("{problem_chirho}\n{USAGE_CHIRHO}");
    ExitCode::from(2)
}
