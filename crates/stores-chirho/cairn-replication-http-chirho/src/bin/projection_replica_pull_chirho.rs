// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pull, verify, and durably mount one feeder-signed account-net projection.

use anyhow::{anyhow, Context, Result};
use cairn_replication_http_chirho::projection_replication_chirho::{
    pull_and_mount_projection_chirho, ProjectionReplicaPullConfigChirho,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<()> {
    let config_path_chirho = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("usage: projection_replica_pull_chirho <config.json>"))?;
    let config_bytes_chirho = std::fs::read(&config_path_chirho).with_context(|| {
        format!("ProjectionReplicaConfigReadRefusedChirho:{config_path_chirho}")
    })?;
    let config_chirho: ProjectionReplicaPullConfigChirho =
        serde_json::from_slice(&config_bytes_chirho)
            .context("ProjectionReplicaConfigParseRefusedChirho")?;
    let observed_at_unix_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("ProjectionReplicaClockRefusedChirho")?
        .as_secs();
    let report_chirho = pull_and_mount_projection_chirho(&config_chirho, observed_at_unix_chirho)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report_chirho)
            .context("ProjectionReplicaReportRenderRefusedChirho")?
    );
    Ok(())
}
