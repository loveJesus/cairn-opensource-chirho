// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! B2.6 replica-serve composition: resolve the pinned source through the operator-signed roster,
//! verify and floor the copied ref snapshot, then construct the GET-only state. This module owns no
//! socket and no lifecycle; the reference binary binds through the crate's private/mesh allowlist.
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/b2-replica-serve-design-chirho.md`.

use crate::ReplicaServeStateChirho;
use anyhow::{bail, Context, Result};
use cairn_replication_chirho::membership_chirho::{
    read_membership_roster_lines_chirho, verify_membership_roster_lines_chirho,
};
use cairn_replication_chirho::ref_snapshot_chirho::{
    mount_latest_verified_snapshot_chirho, RefSnapshotMountReportChirho,
    REF_SNAPSHOT_LOG_FILE_CHIRHO,
};
use cairn_replication_http_chirho::projection_replication_chirho::{
    ProjectionReplicaPullConfigChirho, ReplicaMountedProjectionReadPortChirho,
};
use cairn_replication_http_chirho::ReplicaBalanceReadDagRunnerChirho;
use cairn_store_fs_chirho::FsContentStoreChirho;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaServeConfigChirho {
    pub replica_root_chirho: PathBuf,
    pub listen_addr_chirho: String,
    pub roster_lines_path_chirho: PathBuf,
    pub operator_pubkey_hex_chirho: String,
    pub source_pubkey_hex_chirho: String,
    #[serde(default)]
    pub allow_public_bind_chirho: bool,
    #[serde(default)]
    pub balance_read_chirho: Option<ReplicaBalanceServeConfigChirho>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaBalanceServeConfigChirho {
    pub projection_chirho: ProjectionReplicaPullConfigChirho,
    pub mode_chirho: ReplicaBalanceReadModeChirho,
    pub max_lag_ms_chirho: u64,
}

/// Production replica serving admits only the ruled CF7 shape. Arbitrary pure-DAG hashes remain an
/// internal R-2 test/future surface and cannot be injected by changing the host config.
#[derive(Clone, Copy, Debug, Deserialize)]
pub enum ReplicaBalanceReadModeChirho {
    #[serde(rename = "direct-verified-mount-chirho")]
    DirectVerifiedMountChirho,
}

pub struct PreparedReplicaServeChirho {
    pub state_chirho: Arc<ReplicaServeStateChirho>,
    pub mount_report_chirho: RefSnapshotMountReportChirho,
    pub source_region_chirho: String,
}

pub fn load_verified_replica_serve_chirho(
    config_chirho: &ReplicaServeConfigChirho,
    verified_at_unix_chirho: u64,
) -> Result<PreparedReplicaServeChirho> {
    if !config_chirho.replica_root_chirho.is_dir() {
        bail!("ReplicaServeRootRefusedChirho: replica root is not an existing directory");
    }
    let roster_lines_chirho =
        read_membership_roster_lines_chirho(&config_chirho.roster_lines_path_chirho)
            .context("ReplicaServeRosterReadRefusedChirho")?;
    let membership_chirho = verify_membership_roster_lines_chirho(
        &roster_lines_chirho,
        &config_chirho.operator_pubkey_hex_chirho,
    )
    .context("ReplicaServeRosterVerificationRefusedChirho")?;
    if !membership_chirho.is_active_source_chirho(&config_chirho.source_pubkey_hex_chirho) {
        bail!("ReplicaServeSourceMembershipRefusedChirho");
    }
    let source_region_chirho = membership_chirho
        .region_of_chirho(&config_chirho.source_pubkey_hex_chirho)
        .unwrap_or("")
        .to_string();

    let snapshot_log_chirho = std::fs::read(
        config_chirho
            .replica_root_chirho
            .join(REF_SNAPSHOT_LOG_FILE_CHIRHO),
    )
    .context("ReplicaServeSnapshotLogReadRefusedChirho")?;
    let store_chirho = FsContentStoreChirho::new_chirho(&config_chirho.replica_root_chirho);
    let (view_chirho, mount_report_chirho) = mount_latest_verified_snapshot_chirho(
        &store_chirho,
        &config_chirho.replica_root_chirho,
        &snapshot_log_chirho,
        &config_chirho.source_pubkey_hex_chirho,
        verified_at_unix_chirho,
    )
    .context("ReplicaServeSnapshotMountRefusedChirho")?;
    let mut state_chirho =
        ReplicaServeStateChirho::new_chirho(store_chirho, view_chirho, mount_report_chirho.clone());
    if let Some(balance_read_chirho) = &config_chirho.balance_read_chirho {
        if balance_read_chirho.projection_chirho.replica_root_chirho
            != config_chirho.replica_root_chirho
        {
            bail!("ReplicaServeBalanceRootMismatchChirho");
        }
        let projection_read_port_chirho = ReplicaMountedProjectionReadPortChirho::new_chirho(
            balance_read_chirho.projection_chirho.clone(),
            verified_at_unix_chirho.saturating_mul(1_000),
            balance_read_chirho.max_lag_ms_chirho,
        );
        let pinned_mount_coordinate_chirho = projection_read_port_chirho
            .current_mount_coordinate_chirho()
            .context("ReplicaServeBalanceMountVerificationRefusedChirho")?;
        let dag_chirho = match balance_read_chirho.mode_chirho {
            ReplicaBalanceReadModeChirho::DirectVerifiedMountChirho => {
                ReplicaBalanceReadDagRunnerChirho::direct_verified_mount_dag_chirho(
                    &pinned_mount_coordinate_chirho,
                )
            }
        };
        let runner_chirho = ReplicaBalanceReadDagRunnerChirho::new_pinned_chirho(
            projection_read_port_chirho,
            pinned_mount_coordinate_chirho,
        );
        state_chirho = ReplicaServeStateChirho::attach_balance_read_chirho(
            state_chirho,
            runner_chirho,
            dag_chirho,
        );
    }
    Ok(PreparedReplicaServeChirho {
        state_chirho,
        mount_report_chirho,
        source_region_chirho,
    })
}
