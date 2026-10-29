// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Source-side P3/B2 export command. This is writer-region tooling: it creates real signed Gate 1
//! anchors/head plus the signed app/app-route ref snapshot before the separately read-only HTTP
//! source is started. Configuration carries paths only; no key bytes leave the source root.

use anyhow::{anyhow, Context, Result};
use cairn_chirho::replication_source_export_chirho::prepare_replication_source_chirho;
use serde::Deserialize;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceExportConfigChirho {
    source_root_chirho: PathBuf,
    gate1_head_output_path_chirho: PathBuf,
}

fn main() -> Result<()> {
    let config_path_chirho = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("usage: replication_source_export_chirho <config.json>"))?;
    let config_bytes_chirho = std::fs::read(&config_path_chirho).with_context(|| {
        format!("ReplicationSourceExportConfigReadRefusedChirho:{config_path_chirho}")
    })?;
    let config_chirho: SourceExportConfigChirho = serde_json::from_slice(&config_bytes_chirho)
        .context("ReplicationSourceExportConfigParseRefusedChirho")?;
    let source_time_unix_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("ReplicationSourceClockRefusedChirho")?
        .as_secs();
    let report_chirho = prepare_replication_source_chirho(
        &config_chirho.source_root_chirho,
        &config_chirho.gate1_head_output_path_chirho,
        source_time_unix_chirho,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report_chirho)
            .context("ReplicationSourceExportReportRenderRefusedChirho")?
    );
    Ok(())
}
