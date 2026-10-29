// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Thin read-only porcelain for one configured live F1 mirror high-water report.

use crate::args_chirho::CommandChirho;
use cairn_ledger_geo_node_chirho::a6_authority_composition_chirho::{
    configured_ledger_mirror_live_head_report_read_only_chirho,
    ledger_mirror_live_head_bound_verdict_bytes_chirho,
    ledger_mirror_live_head_report_bytes_chirho, MAX_LEDGER_MIRROR_LIVE_HEAD_REPORT_BYTES_CHIRHO,
};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

pub(crate) fn handle_ledger_mirror_live_head_command_chirho(
    selected_root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    let Some(bytes_chirho) = ledger_mirror_live_head_command_bytes_with_chirho(
        selected_root_chirho,
        command_chirho,
        |selected_root_chirho, config_path_chirho, expected_config_digest_chirho| {
            let report_chirho = configured_ledger_mirror_live_head_report_read_only_chirho(
                selected_root_chirho,
                config_path_chirho,
                expected_config_digest_chirho,
            )?;
            Ok(ledger_mirror_live_head_report_bytes_chirho(&report_chirho)?)
        },
        |report_path_chirho| {
            let report_bytes_chirho = read_bounded_live_head_report_chirho(report_path_chirho)?;
            Ok(ledger_mirror_live_head_bound_verdict_bytes_chirho(
                &report_bytes_chirho,
            )?)
        },
    )?
    else {
        return Ok(false);
    };
    let mut stdout_chirho = std::io::stdout().lock();
    // These bytes are the digest-bound artifact. Adding CLI framing would change what the verdict
    // verifies, so the serializers own the complete stdout population.
    stdout_chirho.write_all(&bytes_chirho)?;
    Ok(true)
}

fn ledger_mirror_live_head_command_bytes_with_chirho<ReportBytesChirho, VerdictBytesChirho>(
    selected_root_chirho: &Path,
    command_chirho: &CommandChirho,
    report_bytes_chirho: ReportBytesChirho,
    verdict_bytes_chirho: VerdictBytesChirho,
) -> anyhow::Result<Option<Vec<u8>>>
where
    ReportBytesChirho: FnOnce(&Path, &Path, &str) -> anyhow::Result<Vec<u8>>,
    VerdictBytesChirho: FnOnce(&Path) -> anyhow::Result<Vec<u8>>,
{
    match command_chirho {
        CommandChirho::LedgerMirrorLiveHeadReportChirho(args_chirho) => report_bytes_chirho(
            selected_root_chirho,
            &args_chirho.config_path_chirho,
            &args_chirho.expected_config_digest_chirho,
        )
        .map(Some),
        CommandChirho::LedgerMirrorLiveHeadVerdictChirho(args_chirho) => {
            verdict_bytes_chirho(&args_chirho.report_path_chirho).map(Some)
        }
        _ => Ok(None),
    }
}

fn read_bounded_live_head_report_chirho(report_path_chirho: &Path) -> anyhow::Result<Vec<u8>> {
    let metadata_chirho = fs::symlink_metadata(report_path_chirho)
        .map_err(|_| anyhow::anyhow!("LedgerMirrorLiveHeadVerdictReportInputRefusedChirho"))?;
    if !metadata_chirho.file_type().is_file()
        || metadata_chirho.len() == 0
        || metadata_chirho.len() > MAX_LEDGER_MIRROR_LIVE_HEAD_REPORT_BYTES_CHIRHO as u64
    {
        anyhow::bail!("LedgerMirrorLiveHeadVerdictReportInputRefusedChirho");
    }
    let file_chirho = fs::File::open(report_path_chirho)
        .map_err(|_| anyhow::anyhow!("LedgerMirrorLiveHeadVerdictReportInputRefusedChirho"))?;
    let opened_metadata_chirho = file_chirho
        .metadata()
        .map_err(|_| anyhow::anyhow!("LedgerMirrorLiveHeadVerdictReportInputRefusedChirho"))?;
    if !opened_metadata_chirho.file_type().is_file()
        || opened_metadata_chirho.len() == 0
        || opened_metadata_chirho.len() > MAX_LEDGER_MIRROR_LIVE_HEAD_REPORT_BYTES_CHIRHO as u64
    {
        anyhow::bail!("LedgerMirrorLiveHeadVerdictReportInputRefusedChirho");
    }
    read_bounded_live_head_report_stream_chirho(file_chirho)
}

fn read_bounded_live_head_report_stream_chirho<ReaderChirho: Read>(
    reader_chirho: ReaderChirho,
) -> anyhow::Result<Vec<u8>> {
    let mut bytes_chirho = Vec::new();
    reader_chirho
        .take((MAX_LEDGER_MIRROR_LIVE_HEAD_REPORT_BYTES_CHIRHO as u64) + 1)
        .read_to_end(&mut bytes_chirho)
        .map_err(|_| anyhow::anyhow!("LedgerMirrorLiveHeadVerdictReportInputRefusedChirho"))?;
    if bytes_chirho.is_empty()
        || bytes_chirho.len() > MAX_LEDGER_MIRROR_LIVE_HEAD_REPORT_BYTES_CHIRHO
    {
        anyhow::bail!("LedgerMirrorLiveHeadVerdictReportInputRefusedChirho");
    }
    Ok(bytes_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::args_chirho::CliChirho;
    use crate::cli_context_chirho::CliContextChirho;
    use clap::Parser;

    fn input_refusal_chirho(path_chirho: &Path) -> String {
        read_bounded_live_head_report_chirho(path_chirho)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn report_command_keeps_the_selected_root_and_requires_the_reviewed_config_digest_chirho() {
        let expected_config_digest_chirho = "11".repeat(32);
        let cli_chirho = CliChirho::try_parse_from([
            "cairn-chirho",
            "--root",
            "/private/configured-root-chirho",
            "ledger-mirror-live-head-report-chirho",
            "--config-chirho",
            "/private/configured-root-chirho/cairn-chirho.toml",
            "--expected-config-digest-chirho",
            &expected_config_digest_chirho,
        ])
        .unwrap();
        let context_chirho = CliContextChirho::from_cli_chirho(&cli_chirho).unwrap();
        assert_eq!(
            context_chirho.root_chirho(),
            Path::new("/private/configured-root-chirho")
        );
        let CommandChirho::LedgerMirrorLiveHeadReportChirho(args_chirho) =
            cli_chirho.command_chirho
        else {
            panic!("live mirror head report command was not selected");
        };
        assert_eq!(
            args_chirho.config_path_chirho,
            Path::new("/private/configured-root-chirho/cairn-chirho.toml")
        );
        assert_eq!(
            args_chirho.expected_config_digest_chirho,
            expected_config_digest_chirho
        );
    }

    #[test]
    fn report_command_routes_the_selected_root_and_config_in_exact_roles_chirho() {
        let selected_root_chirho = Path::new("/private/configured-root-chirho");
        let config_path_chirho = Path::new("/private/configured-root-chirho/cairn-chirho.toml");
        let expected_config_digest_chirho = "22".repeat(32);
        assert_ne!(selected_root_chirho, config_path_chirho);
        let cli_chirho = CliChirho::try_parse_from([
            "cairn-chirho",
            "--root",
            selected_root_chirho.to_str().unwrap(),
            "ledger-mirror-live-head-report-chirho",
            "--config-chirho",
            config_path_chirho.to_str().unwrap(),
            "--expected-config-digest-chirho",
            &expected_config_digest_chirho,
        ])
        .unwrap();
        let context_chirho = CliContextChirho::from_cli_chirho(&cli_chirho).unwrap();
        let expected_bytes_chirho = b"exact-live-head-report-bytes-chirho\n".to_vec();
        let bytes_chirho = ledger_mirror_live_head_command_bytes_with_chirho(
            context_chirho.root_chirho(),
            &cli_chirho.command_chirho,
            |routed_root_chirho, routed_config_chirho, routed_digest_chirho| {
                assert_eq!(routed_root_chirho, selected_root_chirho);
                assert_eq!(routed_config_chirho, config_path_chirho);
                assert_eq!(routed_digest_chirho, expected_config_digest_chirho);
                Ok(expected_bytes_chirho.clone())
            },
            |_| -> anyhow::Result<Vec<u8>> {
                panic!("report command unexpectedly entered the verdict route")
            },
        )
        .unwrap()
        .expect("report command must be handled");
        assert_eq!(bytes_chirho, expected_bytes_chirho);
    }

    #[test]
    fn report_command_has_no_caller_selected_authority_coordinate_chirho() {
        let expected_config_digest_chirho = "33".repeat(32);
        for forbidden_chirho in [
            "--node-id-chirho",
            "--writer-node-id-chirho",
            "--holder-node-id-chirho",
            "--tail-digest-chirho",
            "--sign-root-chirho",
        ] {
            let refusal_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "ledger-mirror-live-head-report-chirho",
                "--config-chirho",
                "/private/configured-root-chirho/cairn-chirho.toml",
                "--expected-config-digest-chirho",
                &expected_config_digest_chirho,
                forbidden_chirho,
                "caller-value-chirho",
            ])
            .err()
            .expect("caller-selected authority unexpectedly entered the CLI grammar");
            assert!(refusal_chirho.to_string().contains(forbidden_chirho));
        }
    }

    #[test]
    fn verdict_command_exposes_only_the_captured_report_chirho() {
        let cli_chirho = CliChirho::try_parse_from([
            "cairn-chirho",
            "ledger-mirror-live-head-verdict-chirho",
            "--report-chirho",
            "/private/capture-chirho/live-head-report-chirho.json",
        ])
        .unwrap();
        let CommandChirho::LedgerMirrorLiveHeadVerdictChirho(args_chirho) =
            cli_chirho.command_chirho
        else {
            panic!("live mirror head verdict command was not selected");
        };
        assert_eq!(
            args_chirho.report_path_chirho,
            Path::new("/private/capture-chirho/live-head-report-chirho.json")
        );
    }

    #[test]
    fn verdict_report_stream_is_bounded_before_the_full_input_is_read_chirho() {
        let exact_limit_chirho = vec![b'a'; MAX_LEDGER_MIRROR_LIVE_HEAD_REPORT_BYTES_CHIRHO];
        assert_eq!(
            read_bounded_live_head_report_stream_chirho(std::io::Cursor::new(&exact_limit_chirho))
                .unwrap(),
            exact_limit_chirho
        );
        let oversized_chirho = vec![b'a'; MAX_LEDGER_MIRROR_LIVE_HEAD_REPORT_BYTES_CHIRHO + 1];
        assert_eq!(
            read_bounded_live_head_report_stream_chirho(std::io::Cursor::new(oversized_chirho))
                .unwrap_err()
                .to_string(),
            "LedgerMirrorLiveHeadVerdictReportInputRefusedChirho"
        );
    }

    #[test]
    fn verdict_report_file_refuses_empty_wrong_type_symlink_and_oversize_chirho() {
        let unique_chirho = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root_chirho = std::env::temp_dir().join(format!(
            "cairn-live-head-cli-{}-{unique_chirho}-chirho",
            std::process::id()
        ));
        fs::create_dir(&root_chirho).unwrap();

        let exact_path_chirho = root_chirho.join("exact-report-chirho.json");
        let exact_bytes_chirho = vec![b'a'; MAX_LEDGER_MIRROR_LIVE_HEAD_REPORT_BYTES_CHIRHO];
        fs::write(&exact_path_chirho, &exact_bytes_chirho).unwrap();
        assert_eq!(
            read_bounded_live_head_report_chirho(&exact_path_chirho).unwrap(),
            exact_bytes_chirho
        );

        let empty_path_chirho = root_chirho.join("empty-report-chirho.json");
        fs::write(&empty_path_chirho, b"").unwrap();
        let directory_path_chirho = root_chirho.join("directory-report-chirho");
        fs::create_dir(&directory_path_chirho).unwrap();
        let oversized_path_chirho = root_chirho.join("oversized-report-chirho.json");
        fs::write(
            &oversized_path_chirho,
            vec![b'a'; MAX_LEDGER_MIRROR_LIVE_HEAD_REPORT_BYTES_CHIRHO + 1],
        )
        .unwrap();

        for refused_path_chirho in [
            empty_path_chirho.as_path(),
            directory_path_chirho.as_path(),
            oversized_path_chirho.as_path(),
        ] {
            assert_eq!(
                input_refusal_chirho(refused_path_chirho),
                "LedgerMirrorLiveHeadVerdictReportInputRefusedChirho"
            );
        }

        #[cfg(unix)]
        {
            let symlink_path_chirho = root_chirho.join("symlink-report-chirho.json");
            std::os::unix::fs::symlink(&exact_path_chirho, &symlink_path_chirho).unwrap();
            assert_eq!(
                input_refusal_chirho(&symlink_path_chirho),
                "LedgerMirrorLiveHeadVerdictReportInputRefusedChirho"
            );
        }

        fs::remove_dir_all(root_chirho).unwrap();
    }
}
