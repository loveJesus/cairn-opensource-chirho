// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Reference replica PULL client: performs the full Gate1/hash-verifying HTTP sync, then durably
//! carries, verifies, floors, and mounts the signed B2 app/app-route ref snapshot. A success report
//! therefore means both independent verification planes passed; it never means the replica is
//! current beyond the source-export/pull cadence.

use anyhow::{anyhow, Context, Result};
use cairn_replication_http_chirho::pull_chirho::{
    pull_and_verify_http_replica_chirho, HttpReplicaPullConfigChirho,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<()> {
    let config_path_chirho = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("usage: replica_pull_chirho <config.json>"))?;
    let config_bytes_chirho = std::fs::read(&config_path_chirho)
        .with_context(|| format!("HttpReplicaConfigReadRefusedChirho:{config_path_chirho}"))?;
    let config_chirho: HttpReplicaPullConfigChirho =
        serde_json::from_slice(&config_bytes_chirho)
            .context("HttpReplicaConfigParseRefusedChirho")?;
    let verified_at_unix_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("HttpReplicaClockRefusedChirho")?
        .as_secs();
    let report_chirho =
        pull_and_verify_http_replica_chirho(&config_chirho, verified_at_unix_chirho)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report_chirho)
            .context("HttpReplicaReportRenderRefusedChirho")?
    );
    Ok(())
}
