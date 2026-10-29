// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Reference replica PULL client from an S3-compatible BUCKET (Garage/Ceph/MinIO): the same full
//! verified sync as the HTTP `replica_pull_chirho` — objects hash-verify into the served replica
//! store (mismatches quarantined, never served), the anchor + Ring-A logs copy verbatim, the
//! independent fold must reproduce the source-signed digests against the operator-signed roster
//! and pinned source key, and the durable per-replica-root anti-rollback floor
//! (`replica-sync-floor-chirho.json`, transport-independent) is read before and raised after every
//! success. Additionally carries the B2 ref-snapshot log (`ref-snapshot-log-chirho.jsonl`) down
//! verbatim when the bucket offers it — untrusted carriage; the replica-serve mount verifies every
//! row against the pinned source key before anything is served. Prints a schema-tagged report.
//! Part of the distributed-HA Pillar B workflow
//! (`spec-chirho/workflows-chirho/distributed-ha-chirho/pillar-b-storage-read-path-chirho.md`).

use anyhow::{anyhow, Context, Result};
use cairn_durable_chirho::write_file_durable_chirho;
use cairn_replication_chirho::membership_chirho::read_membership_roster_lines_chirho;
use cairn_replication_chirho::receiver_chirho::{
    receive_and_verify_replica_chirho, ReplicaSyncReportChirho,
};
use cairn_replication_chirho::ref_snapshot_chirho::REF_SNAPSHOT_LOG_FILE_CHIRHO;
use cairn_replication_chirho::sync_floor_chirho::{
    read_sync_floor_chirho, write_sync_floor_chirho,
};
use cairn_replication_chirho::ReplicationSourceChirho;
use cairn_replication_localfs_chirho::FsReplicaQuarantineChirho;
use cairn_store_fs_chirho::FsContentStoreChirho;
use cairn_store_s3_chirho::S3OperatorEndpointConfigChirho;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const S3_PULL_REPORT_SCHEMA_CHIRHO: &str = "s3-replica-pull-report-v1-chirho";

#[derive(Deserialize)]
struct PullConfigChirho {
    /// The bucket endpoint; credentials come ONLY from the named env vars inside.
    s3_chirho: S3OperatorEndpointConfigChirho,
    /// The replica root receiving verified objects, copied logs, and the durable sync floor.
    replica_root_chirho: PathBuf,
    /// Path to the operator-signed membership roster (one JSON record per line).
    roster_lines_path_chirho: PathBuf,
    /// Path to the source-signed anchor head export (JSON bytes, passed through verbatim).
    head_path_chirho: PathBuf,
    /// The pinned OPERATOR pubkey the roster must verify against.
    operator_pubkey_hex_chirho: String,
    /// The pinned SOURCE pubkey; must be an active member of the verified roster.
    source_pubkey_hex_chirho: String,
}

/// The bucket-pull evidence: the standard verified sync report plus whether the B2 ref-snapshot
/// log rode along (byte count only — contents are verified at mount, not here).
#[derive(Serialize)]
struct S3PullReportChirho {
    schema_chirho: String,
    sync_chirho: ReplicaSyncReportChirho,
    ref_snapshot_log_copied_chirho: bool,
    ref_snapshot_log_bytes_chirho: u64,
}

fn main() -> Result<()> {
    let config_path_chirho = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("usage: s3_replica_pull_chirho <config.json>"))?;
    let config_bytes_chirho = std::fs::read(&config_path_chirho)
        .with_context(|| format!("read config {config_path_chirho}"))?;
    let config_chirho: PullConfigChirho =
        serde_json::from_slice(&config_bytes_chirho).context("parse pull config JSON")?;

    let roster_lines_chirho =
        read_membership_roster_lines_chirho(&config_chirho.roster_lines_path_chirho)?;
    let head_bytes_chirho = std::fs::read(&config_chirho.head_path_chirho).with_context(|| {
        format!(
            "read anchor head {}",
            config_chirho.head_path_chirho.display()
        )
    })?;
    std::fs::create_dir_all(&config_chirho.replica_root_chirho).with_context(|| {
        format!(
            "create replica root {}",
            config_chirho.replica_root_chirho.display()
        )
    })?;
    let floor_chirho = read_sync_floor_chirho(&config_chirho.replica_root_chirho)?;

    let source_chirho = config_chirho.s3_chirho.connect_chirho()?;
    let served_chirho = FsContentStoreChirho::new_chirho(&config_chirho.replica_root_chirho);
    let quarantine_chirho =
        FsReplicaQuarantineChirho::new_chirho(&config_chirho.replica_root_chirho);
    let sync_chirho = receive_and_verify_replica_chirho(
        &source_chirho,
        &served_chirho,
        &quarantine_chirho,
        &config_chirho.replica_root_chirho,
        &roster_lines_chirho,
        &config_chirho.operator_pubkey_hex_chirho,
        &config_chirho.source_pubkey_hex_chirho,
        &head_bytes_chirho,
        floor_chirho,
    )
    .context("replica sync failed closed")?;

    write_sync_floor_chirho(
        &config_chirho.replica_root_chirho,
        floor_chirho
            .unwrap_or(0)
            .max(sync_chirho.verified_fold_chirho.anchor_record_count_chirho),
    )?;

    // The receiver copies anchor + Ring-A; the B2 ref-snapshot log is carried explicitly (the one
    // structured allowlist exception). Untrusted carriage — the serve-side mount verifies every
    // row against the pinned source key and the durable snapshot floor before anything serves.
    let mut ref_snapshot_log_copied_chirho = false;
    let mut ref_snapshot_log_bytes_chirho = 0u64;
    if let Some(bytes_chirho) =
        source_chirho.fetch_named_log_chirho(REF_SNAPSHOT_LOG_FILE_CHIRHO)?
    {
        write_file_durable_chirho(
            &config_chirho
                .replica_root_chirho
                .join(REF_SNAPSHOT_LOG_FILE_CHIRHO),
            &bytes_chirho,
        )
        .context("write replica ref-snapshot log")?;
        ref_snapshot_log_copied_chirho = true;
        ref_snapshot_log_bytes_chirho = bytes_chirho.len() as u64;
    }

    let report_chirho = S3PullReportChirho {
        schema_chirho: S3_PULL_REPORT_SCHEMA_CHIRHO.to_string(),
        sync_chirho,
        ref_snapshot_log_copied_chirho,
        ref_snapshot_log_bytes_chirho,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report_chirho).context("render pull report JSON")?
    );
    Ok(())
}
