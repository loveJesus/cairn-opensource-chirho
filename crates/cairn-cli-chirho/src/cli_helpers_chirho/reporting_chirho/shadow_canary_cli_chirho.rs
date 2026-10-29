// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Thin read-only porcelain for the configured shadow-canary report.

use crate::args_chirho::CommandChirho;
use cairn_ledger_host_chirho::{
    configured_shadow_canary_bound_verdict_bytes_chirho,
    configured_shadow_canary_report_bytes_chirho, configured_shadow_canary_report_read_only_chirho,
    ConfiguredShadowCanaryBoundVerdictRequirementsChirho,
    MAX_CONFIGURED_SHADOW_CANARY_REPORT_BYTES_CHIRHO,
};
use std::fs;
use std::io::Write;
use std::path::Path;

/// Emit the node-local report in
/// `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/cf8-canary-window-loss-sequence-chirho.md`.
pub(crate) fn handle_shadow_canary_command_chirho(
    selected_root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    let bytes_chirho = match command_chirho {
        CommandChirho::LedgerShadowCanaryReportChirho(args_chirho) => {
            let report_chirho = configured_shadow_canary_report_read_only_chirho(
                selected_root_chirho,
                &args_chirho.config_path_chirho,
            )?;
            configured_shadow_canary_report_bytes_chirho(&report_chirho)?
        }
        CommandChirho::LedgerShadowCanaryVerdictChirho(args_chirho) => {
            let report_bytes_chirho = read_bounded_report_chirho(&args_chirho.report_path_chirho)?;
            configured_shadow_canary_bound_verdict_bytes_chirho(
                &report_bytes_chirho,
                ConfiguredShadowCanaryBoundVerdictRequirementsChirho {
                    minimum_observation_count_chirho: args_chirho.minimum_observation_count_chirho,
                    minimum_interval_millis_chirho: args_chirho.minimum_interval_millis_chirho,
                },
            )?
        }
        _ => return Ok(false),
    };
    let mut stdout_chirho = std::io::stdout().lock();
    stdout_chirho.write_all(&bytes_chirho)?;
    stdout_chirho.write_all(b"\n")?;
    Ok(true)
}

fn read_bounded_report_chirho(report_path_chirho: &Path) -> anyhow::Result<Vec<u8>> {
    let metadata_chirho = fs::symlink_metadata(report_path_chirho)
        .map_err(|_| anyhow::anyhow!("ShadowCanaryVerdictReportInputRefusedChirho"))?;
    if !metadata_chirho.file_type().is_file()
        || metadata_chirho.len() == 0
        || metadata_chirho.len() > MAX_CONFIGURED_SHADOW_CANARY_REPORT_BYTES_CHIRHO as u64
    {
        anyhow::bail!("ShadowCanaryVerdictReportInputRefusedChirho");
    }
    let bytes_chirho = fs::read(report_path_chirho)
        .map_err(|_| anyhow::anyhow!("ShadowCanaryVerdictReportInputRefusedChirho"))?;
    if bytes_chirho.is_empty()
        || bytes_chirho.len() > MAX_CONFIGURED_SHADOW_CANARY_REPORT_BYTES_CHIRHO
    {
        anyhow::bail!("ShadowCanaryVerdictReportInputRefusedChirho");
    }
    Ok(bytes_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::args_chirho::CliChirho;
    use crate::cli_context_chirho::CliContextChirho;
    use clap::Parser;

    #[test]
    fn report_command_keeps_the_selected_root_and_exposes_only_the_config_chirho() {
        let cli_chirho = CliChirho::try_parse_from([
            "cairn-chirho",
            "--root",
            "/private/configured-root-chirho",
            "ledger-shadow-canary-report-chirho",
            "--config-chirho",
            "/private/configured-root-chirho/cairn-chirho.toml",
        ])
        .unwrap();
        let context_chirho = CliContextChirho::from_cli_chirho(&cli_chirho).unwrap();
        assert_eq!(
            context_chirho.root_chirho(),
            Path::new("/private/configured-root-chirho")
        );
        let CommandChirho::LedgerShadowCanaryReportChirho(args_chirho) = cli_chirho.command_chirho
        else {
            panic!("shadow canary report command was not selected");
        };
        assert_eq!(
            args_chirho.config_path_chirho,
            Path::new("/private/configured-root-chirho/cairn-chirho.toml")
        );
    }

    #[test]
    fn report_command_has_no_caller_selected_node_coordinate_chirho() {
        let Err(refusal_chirho) = CliChirho::try_parse_from([
            "cairn-chirho",
            "ledger-shadow-canary-report-chirho",
            "--config-chirho",
            "/private/configured-root-chirho/cairn-chirho.toml",
            "--node-id-chirho",
            &"1".repeat(64),
        ]) else {
            panic!("caller-selected node id unexpectedly entered the CLI grammar");
        };
        assert!(refusal_chirho.to_string().contains("--node-id-chirho"));
    }

    #[test]
    fn verdict_command_exposes_only_report_and_bounded_requirements_chirho() {
        let cli_chirho = CliChirho::try_parse_from([
            "cairn-chirho",
            "ledger-shadow-canary-verdict-chirho",
            "--report-chirho",
            "/private/capture-chirho/report-chirho.json",
            "--minimum-observation-count-chirho",
            "2",
            "--minimum-interval-millis-chirho",
            "250",
        ])
        .unwrap();
        let CommandChirho::LedgerShadowCanaryVerdictChirho(args_chirho) = cli_chirho.command_chirho
        else {
            panic!("shadow canary verdict command was not selected");
        };
        assert_eq!(
            args_chirho.report_path_chirho,
            Path::new("/private/capture-chirho/report-chirho.json")
        );
        assert_eq!(args_chirho.minimum_observation_count_chirho, 2);
        assert_eq!(args_chirho.minimum_interval_millis_chirho, 250);
    }
}
