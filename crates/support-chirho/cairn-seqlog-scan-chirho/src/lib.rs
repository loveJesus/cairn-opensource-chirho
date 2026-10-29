// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Thin read-only CLI helper for seqlog recovery preflight evidence (proving no truncation or quarantine is required).

use std::path::Path;

#[derive(Clone, Debug, clap::Args)]
pub struct SeqlogScanArgsChirho {
    #[arg(long = "json")]
    pub json_chirho: bool,
    #[arg(long = "fail-on-findings")]
    pub fail_on_findings_chirho: bool,
}

pub fn run_seqlog_scan_chirho(
    root_chirho: &Path,
    args_chirho: &SeqlogScanArgsChirho,
) -> anyhow::Result<()> {
    let report_chirho = cairn_seqlog_chirho::seqlog_chirho::scan_jsonl_manifest_chirho(
        root_chirho,
        cairn_projection_chirho::projection_chirho::static_surface_manifest_chirho(),
    )?;
    if args_chirho.json_chirho {
        println!("{}", serde_json::to_string_pretty(&report_chirho)?);
    } else {
        println!(
            "seqlog-scan scanned_surfaces={}/{} checked_records={} findings={}",
            report_chirho.scanned_surfaces_chirho,
            report_chirho.total_surfaces_chirho,
            report_chirho.checked_records_chirho,
            report_chirho.findings_chirho.len()
        );
        for finding_chirho in &report_chirho.findings_chirho {
            println!(
                "{}:{}:{} {} - {}",
                finding_chirho.surface_chirho,
                finding_chirho.line_chirho,
                finding_chirho.byte_offset_chirho,
                finding_chirho.kind_chirho,
                finding_chirho.detail_chirho
            );
        }
    }
    if args_chirho.fail_on_findings_chirho && !report_chirho.findings_chirho.is_empty() {
        anyhow::bail!(
            "seqlog-scan found {} finding(s)",
            report_chirho.findings_chirho.len()
        );
    }
    Ok(())
}
