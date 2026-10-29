// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Reference MIRROR client: push one source root into an S3-compatible bucket (Garage/Ceph/MinIO)
//! so the bucket becomes a byte-mirror of the root — every object re-hashed against its address
//! BEFORE upload (push-side M142), only `is_replicable_log_name_chirho` logs uploaded, signing
//! keys / refs / private-blob shred keys never leave by name. Prints `MirrorReportChirho` JSON.
//!
//! TRUST SCOPE: INTERNAL replica-grade buckets ONLY (WG-mesh Garage, private Ceph). The bucket
//! holds ciphertext private blobs and signed logs at the same trust level as a replica root —
//! NEVER point this at a public or customer-facing bucket. Public artifact delivery is a separate
//! GATED export through the M150 public-artifact guard (capability-free, executable-only, by
//! package hash), not a root mirror. Part of the distributed-HA Pillar B workflow
//! (`spec-chirho/workflows-chirho/distributed-ha-chirho/pillar-b-storage-read-path-chirho.md`).

use anyhow::{anyhow, Context, Result};
use cairn_replication_localfs_chirho::LocalFsReplicationSourceChirho;
use cairn_store_s3_chirho::{mirror_source_to_s3_chirho, S3OperatorEndpointConfigChirho};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
struct MirrorConfigChirho {
    /// The source root to mirror (objects + allowlisted logs).
    source_root_chirho: PathBuf,
    /// The bucket endpoint; credentials come ONLY from the named env vars inside.
    s3_chirho: S3OperatorEndpointConfigChirho,
}

fn main() -> Result<()> {
    let config_path_chirho = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("usage: s3_mirror_chirho <config.json>"))?;
    let config_bytes_chirho = std::fs::read(&config_path_chirho)
        .with_context(|| format!("read config {config_path_chirho}"))?;
    let config_chirho: MirrorConfigChirho =
        serde_json::from_slice(&config_bytes_chirho).context("parse mirror config JSON")?;

    let source_chirho =
        LocalFsReplicationSourceChirho::new_chirho(&config_chirho.source_root_chirho);
    let s3_chirho = config_chirho.s3_chirho.connect_chirho()?;
    let report_chirho = mirror_source_to_s3_chirho(&source_chirho, &s3_chirho)
        .map_err(|error_chirho| anyhow!("mirror failed closed: {error_chirho}"))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report_chirho).context("render mirror report JSON")?
    );
    Ok(())
}
