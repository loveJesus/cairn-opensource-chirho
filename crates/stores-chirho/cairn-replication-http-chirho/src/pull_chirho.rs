// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Deployable HTTP pull composition: the full roster/Gate1/hash-verifying receiver followed by
//! durable carriage and verification of the separately signed B2 ref snapshot. Both independent
//! rollback floors must advance successfully before this function reports a usable replica.
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/b2-replica-serve-design-chirho.md`.

use crate::client_chirho::HttpReplicationSourceChirho;
use crate::resolve_bearer_from_env_chirho;
use anyhow::{bail, Context, Result};
use cairn_durable_chirho::write_file_durable_chirho;
use cairn_replication_chirho::membership_chirho::read_membership_roster_lines_chirho;
use cairn_replication_chirho::receiver_chirho::{
    receive_and_verify_replica_chirho, ReplicaSyncReportChirho,
};
use cairn_replication_chirho::ref_snapshot_chirho::{
    mount_latest_verified_snapshot_chirho, RefSnapshotMountReportChirho,
    REF_SNAPSHOT_LOG_FILE_CHIRHO,
};
use cairn_replication_chirho::sync_floor_chirho::{
    read_sync_floor_chirho, write_sync_floor_chirho,
};
use cairn_replication_chirho::ReplicationSourceChirho;
use cairn_replication_localfs_chirho::FsReplicaQuarantineChirho;
use cairn_store_fs_chirho::FsContentStoreChirho;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const HTTP_REPLICA_PULL_REPORT_SCHEMA_CHIRHO: &str = "http-replica-pull-report-v2-chirho";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpReplicaPullConfigChirho {
    pub source_url_chirho: String,
    #[serde(default)]
    pub bearer_env_chirho: Option<String>,
    pub replica_root_chirho: PathBuf,
    pub roster_lines_path_chirho: PathBuf,
    pub head_path_chirho: PathBuf,
    pub operator_pubkey_hex_chirho: String,
    pub source_pubkey_hex_chirho: String,
}

/// Evidence from both verified planes. The object/Gate1 report and the ref-snapshot mount report
/// remain distinct so neither floor can be mistaken for covering the other.
#[derive(Clone, Debug, Serialize)]
pub struct HttpReplicaPullReportChirho {
    pub schema_chirho: String,
    pub sync_chirho: ReplicaSyncReportChirho,
    pub ref_snapshot_log_bytes_chirho: u64,
    pub ref_snapshot_mount_chirho: RefSnapshotMountReportChirho,
}

pub fn pull_and_verify_http_replica_chirho(
    config_chirho: &HttpReplicaPullConfigChirho,
    verified_at_unix_chirho: u64,
) -> Result<HttpReplicaPullReportChirho> {
    let bearer_chirho = resolve_bearer_from_env_chirho(config_chirho.bearer_env_chirho.as_deref())
        .context("HttpReplicaBearerRefusedChirho")?;
    let roster_lines_chirho =
        read_membership_roster_lines_chirho(&config_chirho.roster_lines_path_chirho)
            .context("HttpReplicaRosterReadRefusedChirho")?;
    let head_bytes_chirho = std::fs::read(&config_chirho.head_path_chirho)
        .context("HttpReplicaGate1HeadReadRefusedChirho")?;
    std::fs::create_dir_all(&config_chirho.replica_root_chirho)
        .context("HttpReplicaRootCreateRefusedChirho")?;
    let sync_floor_chirho = read_sync_floor_chirho(&config_chirho.replica_root_chirho)
        .context("HttpReplicaSyncFloorReadRefusedChirho")?;

    let source_chirho =
        HttpReplicationSourceChirho::new_chirho(&config_chirho.source_url_chirho, bearer_chirho);
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
        sync_floor_chirho,
    )
    .context("HttpReplicaGate1SyncRefusedChirho")?;

    write_sync_floor_chirho(
        &config_chirho.replica_root_chirho,
        sync_floor_chirho
            .unwrap_or(0)
            .max(sync_chirho.verified_fold_chirho.anchor_record_count_chirho),
    )
    .context("HttpReplicaSyncFloorWriteRefusedChirho")?;

    let snapshot_log_chirho = source_chirho
        .fetch_named_log_chirho(REF_SNAPSHOT_LOG_FILE_CHIRHO)
        .context("HttpReplicaSnapshotFetchRefusedChirho")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "HttpReplicaSnapshotMissingChirho: source has no {REF_SNAPSHOT_LOG_FILE_CHIRHO}"
            )
        })?;
    if snapshot_log_chirho.is_empty() {
        bail!("HttpReplicaSnapshotEmptyChirho");
    }
    write_file_durable_chirho(
        &config_chirho
            .replica_root_chirho
            .join(REF_SNAPSHOT_LOG_FILE_CHIRHO),
        &snapshot_log_chirho,
    )
    .context("HttpReplicaSnapshotWriteRefusedChirho")?;
    let (_view_chirho, ref_snapshot_mount_chirho) = mount_latest_verified_snapshot_chirho(
        &served_chirho,
        &config_chirho.replica_root_chirho,
        &snapshot_log_chirho,
        &config_chirho.source_pubkey_hex_chirho,
        verified_at_unix_chirho,
    )
    .context("HttpReplicaSnapshotMountRefusedChirho")?;

    Ok(HttpReplicaPullReportChirho {
        schema_chirho: HTTP_REPLICA_PULL_REPORT_SCHEMA_CHIRHO.to_string(),
        sync_chirho,
        ref_snapshot_log_bytes_chirho: snapshot_log_chirho.len() as u64,
        ref_snapshot_mount_chirho,
    })
}
